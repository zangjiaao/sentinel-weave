from pathlib import Path
import os


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _path_env(name: str, default: Path) -> Path:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return Path(raw_value).expanduser()


def _load_env_file(path: Path, *, override: bool = False) -> None:
    if not path.exists():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].strip()
        if "=" not in stripped:
            continue

        key, raw_value = stripped.split("=", 1)
        key = key.strip()
        if not key:
            continue

        value = raw_value.strip()
        is_quoted = (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {'"', "'"}
        )
        if is_quoted:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()

        if override or key not in os.environ:
            os.environ[key] = value


PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent
_load_env_file(PROJECT_ROOT / ".env", override=False)
FIXTURE_DIR = PROJECT_ROOT / "fixtures" / "spike"
SPIKE_MEMORY_DIR = PROJECT_ROOT / "fixtures" / "spike_memory"
DEFAULT_DB_PATH = PROJECT_ROOT / "spike.db"
DEFAULT_MEMORY_SPIKE_DB_PATH = PROJECT_ROOT / "memory-spike.db"
DEFAULT_HERMES_HOME = _path_env("HERMES_HOME", Path.home() / ".hermes")
DEFAULT_HERMES_PATROL_HOME = _path_env("HERMES_PATROL_HOME", Path.home() / ".hermes-patrol")
DEFAULT_HERMES_CRON_JOB_ID = os.getenv("HERMES_PATROL_JOB_ID", "d27a82c0fa79")
DEFAULT_HERMES_PATROL_TRIGGER_MODE = os.getenv("HERMES_PATROL_TRIGGER_MODE", "chat")
DEFAULT_HERMES_PATROL_MAX_TURNS = _int_env("HERMES_PATROL_MAX_TURNS", 18)
DEFAULT_HERMES_PATROL_PROMPT_PATH = _path_env(
    "HERMES_PATROL_PROMPT_PATH",
    PROJECT_ROOT / "hermes" / "patrol-prompt.md",
)
DEFAULT_OPENAI_PATROL_MODEL = os.getenv("OPENAI_PATROL_MODEL", "gpt-5-mini")
DEFAULT_OPENAI_BASE_URL = (os.getenv("OPENAI_BASE_URL") or "").strip() or None
DEFAULT_OPENAI_PATROL_TOOL_PROFILE = (os.getenv("OPENAI_PATROL_TOOL_PROFILE") or "compact").strip().lower()
DEFAULT_OPENAI_PATROL_RESUME_COMPACT_INSTRUCTIONS = _bool_env(
    "OPENAI_PATROL_RESUME_COMPACT_INSTRUCTIONS",
    True,
)
DEFAULT_NEUTRAL_CASE_LINK_GUARD = _bool_env("NEUTRAL_CASE_LINK_GUARD", True)
