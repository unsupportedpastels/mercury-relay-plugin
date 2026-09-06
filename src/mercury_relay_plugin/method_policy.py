"""Pure fail-closed policy for JSON-RPC requests entering Mercury Relay."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from .config import validate_profile_id
from .strict_json import StrictJsonError, loads_strict

# The full normal-client session surface the released mobile apps use over
# the official /api/ws gateway. The relay controller runs with
# auth_identity=None, so nothing here grants more than an ordinary ticketed
# client; privileged browser-controller operations stay unavailable.
ALLOWED_V1_METHODS = frozenset(
    {
        "approval.respond",
        "clarify.respond",
        "complete.slash",
        "config.set",
        "cron.manage",
        # Read-only official status used when a retained child is reconciled.
        "delegation.status",
        "file.attach",
        "gateway.ping",
        "image.attach_bytes",
        "model.options",
        "process.list",
        "profiles.list",
        "projects.create",
        "projects.delete",
        "projects.project_sessions",
        "projects.set_active",
        "projects.tree",
        "prompt.submit",
        "session.active_list",
        "session.branch",
        "session.close",
        "session.compress",
        "session.context_breakdown",
        "session.create",
        "session.history",
        "session.interrupt",
        "session.resume",
        "session.steer",
        "session.undo",
        "session.usage",
    }
)
_PRIVILEGED_IDENTITY_FIELDS = frozenset({"auth_identity", "principal_id"})
_REQUEST_FIELDS = frozenset({"jsonrpc", "id", "method", "params"})


class MethodPolicyRejected(ValueError):
    """A non-oracular policy rejection carrying one stable reason code."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class MethodPolicy:
    """Validate one installation-scoped request while preserving its exact bytes."""

    def __init__(
        self,
        *,
        profile: str,
        allowed_methods: frozenset[str] = ALLOWED_V1_METHODS,
        profile_authorizer: Callable[[str], bool] | None = None,
    ):
        if not isinstance(profile, str) or not profile:
            raise ValueError("profile must be non-empty")
        if not isinstance(allowed_methods, frozenset) or not allowed_methods:
            raise ValueError("allowed_methods must be a non-empty frozenset")
        if profile_authorizer is not None and not callable(profile_authorizer):
            raise ValueError("profile_authorizer must be callable")
        self.profile = profile
        self.allowed_methods = allowed_methods
        self.profile_authorizer = profile_authorizer

    def validate_text(self, raw: str) -> str:
        if not isinstance(raw, str):
            raise MethodPolicyRejected("invalid_request")
        try:
            request = loads_strict(raw)
        except StrictJsonError:
            raise MethodPolicyRejected("invalid_json") from None
        if not isinstance(request, Mapping) or request.get("jsonrpc") != "2.0":
            raise MethodPolicyRejected("invalid_request")
        if not set(request).issubset(_REQUEST_FIELDS):
            raise MethodPolicyRejected("invalid_request")

        request_id = request.get("id")
        if (
            request_id is None
            or isinstance(request_id, bool)
            or not isinstance(request_id, (str, int))
            or (isinstance(request_id, str) and not request_id)
        ):
            raise MethodPolicyRejected("uncorrelated_request")

        method = request.get("method")
        if not isinstance(method, str) or method not in self.allowed_methods:
            raise MethodPolicyRejected("method_not_allowed")

        params = request.get("params", {})
        if not isinstance(params, Mapping):
            raise MethodPolicyRejected("invalid_params")
        if any(field in params for field in _PRIVILEGED_IDENTITY_FIELDS):
            raise MethodPolicyRejected("privileged_identity")

        requested_profile = params.get("profile")
        if requested_profile is not None:
            if not isinstance(requested_profile, str):
                raise MethodPolicyRejected("invalid_params")
            try:
                validate_profile_id(requested_profile)
                permitted = (
                    self.profile_authorizer(requested_profile) is True
                    if self.profile_authorizer is not None
                    else requested_profile == self.profile
                )
            except Exception:
                permitted = False
            if not permitted:
                raise MethodPolicyRejected("profile_not_available")

        return raw
