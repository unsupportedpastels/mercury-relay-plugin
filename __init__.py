"""Hermes host-plugin registration for Mercury Relay."""

from __future__ import annotations

import logging

logger = logging.getLogger("mercury_relay_plugin.host")

SYSTEM_PROMPT_SECTION_ID = "mercury-relay.inline-media"
SYSTEM_PROMPT_SECTION_MAX_CHARS = 1_200
INLINE_MEDIA_GUIDANCE = (
    "Mercury inline image delivery\n"
    "A conversation may be viewed in Mercury even when it began in another Hermes "
    "interface, including the Hermes TUI. Do not infer that native image delivery is "
    "unavailable merely from the interface where the conversation began.\n\n"
    "When delivering an actual host-local image, first verify that its absolute path "
    "points to an existing regular file and that its format and size are supported by "
    "the applicable delivery path. Then emit exactly `MEDIA:/absolute/path.png` as a "
    "standalone line, substituting the verified file's actual absolute path, outside "
    "Markdown links or images, inline backticks, code fences, and lists.\n\n"
    "Mercury Relay image reads support PNG, JPEG, GIF, WebP, and BMP files up to 2 MiB. "
    "Other direct Hermes delivery paths may support different formats and size limits; "
    "2 MiB is not a universal direct-delivery limit. Emitting a MEDIA line requests "
    "delivery but does not by itself prove that delivery succeeded."
)


def register(ctx) -> None:
    """Register cache-safe media guidance when the host API is available."""

    register_section = getattr(ctx, "register_system_prompt_section", None)
    if not callable(register_section):
        logger.warning(
            "Hermes host has no register_system_prompt_section API; "
            "Mercury inline-media guidance was not registered"
        )
        return

    register_section(
        SYSTEM_PROMPT_SECTION_ID,
        INLINE_MEDIA_GUIDANCE,
        position="after_memory",
        max_chars=SYSTEM_PROMPT_SECTION_MAX_CHARS,
    )
