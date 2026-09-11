from __future__ import annotations

import importlib.util
import logging
from pathlib import Path

PLUGIN_ROOT = Path(__file__).parents[1]


def _load_host_plugin():
    spec = importlib.util.spec_from_file_location(
        "mercury_relay_host_plugin", PLUGIN_ROOT / "__init__.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PromptSectionContext:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def register_system_prompt_section(self, *args, **kwargs) -> None:
        self.calls.append((args, kwargs))


class LegacyContext:
    pass


def test_register_adds_static_bounded_inline_media_guidance() -> None:
    plugin = _load_host_plugin()
    ctx = PromptSectionContext()

    plugin.register(ctx)

    assert ctx.calls == [
        (
            (plugin.SYSTEM_PROMPT_SECTION_ID, plugin.INLINE_MEDIA_GUIDANCE),
            {
                "position": "after_memory",
                "max_chars": plugin.SYSTEM_PROMPT_SECTION_MAX_CHARS,
            },
        )
    ]
    assert isinstance(plugin.INLINE_MEDIA_GUIDANCE, str)
    assert not callable(plugin.INLINE_MEDIA_GUIDANCE)
    assert len(plugin.INLINE_MEDIA_GUIDANCE) <= plugin.SYSTEM_PROMPT_SECTION_MAX_CHARS


def test_guidance_is_stable_and_states_delivery_boundaries() -> None:
    first = _load_host_plugin()
    second = _load_host_plugin()

    assert first.INLINE_MEDIA_GUIDANCE == second.INLINE_MEDIA_GUIDANCE
    guidance = first.INLINE_MEDIA_GUIDANCE
    assert "may be viewed in Mercury" in guidance
    assert "Hermes TUI" in guidance
    assert "Do not infer" in guidance
    assert "MEDIA:/absolute/path.png" in guidance
    assert "standalone line" in guidance
    assert "outside Markdown" in guidance
    assert "existing regular file" in guidance
    assert "format and size are supported" in guidance
    assert "size limits" in guidance
    assert "PNG, JPEG, GIF, WebP, and BMP" in guidance
    assert "2 MiB" in guidance
    assert "not a universal" in guidance
    assert "currently viewed in Mercury" not in guidance


def test_register_warns_and_skips_on_older_host_without_prompt_section_api(
    caplog,
) -> None:
    plugin = _load_host_plugin()

    with caplog.at_level(logging.WARNING, logger="mercury_relay_plugin.host"):
        plugin.register(LegacyContext())

    assert "register_system_prompt_section" in caplog.text
    assert "inline-media guidance was not registered" in caplog.text
