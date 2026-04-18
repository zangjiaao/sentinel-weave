import importlib
import os
from pathlib import Path
import sys
import types


def test_load_env_file_sets_missing_and_keeps_existing(monkeypatch, tmp_path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "OPENAI_BASE_URL=https://api.example.test/v1",
                "EXISTING_KEY=from_env_file",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setenv("EXISTING_KEY", "already_set")

    import security_analyst_agent.config as config

    config._load_env_file(env_path, override=False)

    assert os.getenv("OPENAI_BASE_URL") == "https://api.example.test/v1"
    assert os.getenv("EXISTING_KEY") == "already_set"


def test_default_openai_client_factory_uses_base_url(monkeypatch) -> None:
    captured_kwargs: dict[str, str] = {}

    class _FakeOpenAI:
        def __init__(self, **kwargs) -> None:
            captured_kwargs.update(kwargs)

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=_FakeOpenAI))

    import security_analyst_agent.openai_patrol_runner as runner

    monkeypatch.setattr(runner, "DEFAULT_OPENAI_BASE_URL", "https://proxy.example.test/v1")
    client = runner._default_openai_client_factory()
    assert isinstance(client, _FakeOpenAI)
    assert captured_kwargs["base_url"] == "https://proxy.example.test/v1"


def test_config_reads_openai_base_url_from_env(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", "https://edge.example.test/v1")
    import security_analyst_agent.config as config

    reloaded = importlib.reload(config)
    assert reloaded.DEFAULT_OPENAI_BASE_URL == "https://edge.example.test/v1"


def test_config_expands_tilde_for_path_env(monkeypatch) -> None:
    monkeypatch.setenv("HERMES_HOME", "~/.hermes")
    monkeypatch.setenv("HERMES_PATROL_HOME", "~/.hermes-patrol")
    monkeypatch.setenv("HERMES_PATROL_PROMPT_PATH", "~/custom/patrol-prompt.md")
    import security_analyst_agent.config as config

    reloaded = importlib.reload(config)
    home = str(Path.home())
    assert str(reloaded.DEFAULT_HERMES_HOME).startswith(home)
    assert str(reloaded.DEFAULT_HERMES_PATROL_HOME).startswith(home)
    assert str(reloaded.DEFAULT_HERMES_PATROL_PROMPT_PATH).startswith(home)
