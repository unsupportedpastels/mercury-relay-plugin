"""Shutdown must settle owned resources before reporting errors/cancellation."""

import asyncio

import pytest
from test_plugin_api import _load_plugin_api
from test_push_preview import preview_bridge

from mercury_relay_plugin.admission import DeviceAdmissionService
from mercury_relay_plugin.authorization import AuthorizationRepository
from mercury_relay_plugin.config import profile_paths
from mercury_relay_plugin.runtime import RelayRuntime
from mercury_relay_plugin.session_lease import SessionLease, SessionLeaseError
from mercury_relay_plugin.virtual_ws import VirtualWebSocket


@pytest.mark.parametrize("fail_controller,cancel,fail_push", [
    (True, False, False), (True, True, False), (False, True, False), (True, False, True),
])
def test_lifespan_drains_every_resource_after_controller_failure(
    tmp_path, fail_controller, cancel, fail_push,
):
    async def run():
        calls = []
        entered, resume = asyncio.Event(), asyncio.Event()

        async def start():
            pass

        async def runtime_close():
            calls.append("runtime")
            await original_runtime_close()

        runtime = RelayRuntime()
        original_runtime_close = runtime.close
        runtime.start = start
        runtime.close = runtime_close
        service = DeviceAdmissionService(
            AuthorizationRepository(profile_paths(explicit_path=tmp_path)), runtime,
            profile="default",
        )
        push = preview_bridge(tmp_path, [])
        push.start()
        service.push = push
        original_push_close = push.close

        async def push_close():
            calls.append("push")
            await original_push_close()
            if fail_push:
                raise RuntimeError("push_cleanup_failed")

        push.close = push_close
        update_metrics = service.metrics.update_active_leases
        close_journal = service.journal.close

        def metrics_close(count):
            calls.append("metrics")
            update_metrics(count)

        def journal_close():
            calls.append("journal")
            close_journal()

        service.metrics.update_active_leases = metrics_close
        service.journal.close = journal_close

        async def controller_close(cid):
            if cid == "first":
                entered.set()
                await resume.wait()
            calls.append(cid)
            if cid == "first" and fail_controller:
                raise RuntimeError("synthetic controller failure")
            return True

        leases = []
        for cid in ("first", "second"):
            lease = SessionLease(
                device_id="synthetic-device", channel=cid, profile="default",
                controller_id=cid, websocket=VirtualWebSocket(), close_controller=controller_close,
            )
            service.leases.register(lease)
            leases.append(lease)
        module = _load_plugin_api()
        module._runtime = runtime
        module._build_admission = lambda _: service
        module._connector_provider = lambda _: None
        module._build_update_checker = lambda _: (_ for _ in ()).throw(RuntimeError("disabled"))
        lifespan = module._lifespan(None)
        await lifespan.__aenter__()
        task = asyncio.create_task(lifespan.__aexit__(None, None, None))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            assert all(lease.released for lease in leases)
            if cancel:
                task.cancel()
                await asyncio.sleep(0)
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done()
            resume.set()
            result = (await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 2))[0]
            assert set(calls) == {"first", "second", "push", "metrics", "journal", "runtime"}
            assert calls[-4:] == ["push", "metrics", "journal", "runtime"]
            assert push._task.done() and push._client.is_closed
            assert module._admission is None and module._connector is None
            if fail_push:
                assert isinstance(result, ExceptionGroup)
                assert any(isinstance(e, SessionLeaseError) for e in result.exceptions)
                assert any(str(e) == "push_cleanup_failed" for e in result.exceptions)
            elif fail_controller:
                assert isinstance(result, SessionLeaseError)
            else:
                assert isinstance(result, asyncio.CancelledError)
            # Repeated admission shutdown observes the same outcome, no double-close.
            before = list(calls)
            await asyncio.gather(service.close(), return_exceptions=True)
            assert calls == before
        finally:
            resume.set()
            await asyncio.gather(task, return_exceptions=True)
            await original_push_close()
            close_journal()

    asyncio.run(run())
