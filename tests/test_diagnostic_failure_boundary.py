from __future__ import annotations

import asyncio

from mercury_relay_plugin.admission import DeviceAdmissionService
from mercury_relay_plugin.authorization import AuthorizationRepository
from mercury_relay_plugin.config import profile_paths
from mercury_relay_plugin.connector import InMemoryHostedConnector, RelayConnectorService
from mercury_relay_plugin.runtime import RelayRuntime


def test_unexpected_session_failure_keeps_safe_exception_category(tmp_path, monkeypatch):
    async def exercise():
        repository = AuthorizationRepository(profile_paths(explicit_path=tmp_path))
        admission = DeviceAdmissionService(repository, RelayRuntime(), profile="default")
        service = RelayConnectorService(admission, InMemoryHostedConnector())

        class Connection:
            closed = False

            async def close(self):
                self.closed = True

        async def fail(connection, connection_id):
            raise ConnectionError("DO NOT LOG: private route and credentials")

        monkeypatch.setattr(service, "_session_loop", fail)
        connection = Connection()
        try:
            assert await service._serve_connection(connection) == "connection_failed"
            assert connection.closed
            events = admission.journal.export()["events"]
            assert events[-1]["exception_category"] == "connection"
            assert "DO NOT LOG" not in str(events)
        finally:
            await admission.close()

    asyncio.run(exercise())
