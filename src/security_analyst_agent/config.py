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


PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent
FIXTURE_DIR = PROJECT_ROOT / "fixtures" / "spike"
SPIKE_MEMORY_DIR = PROJECT_ROOT / "fixtures" / "spike_memory"
DEFAULT_DB_PATH = PROJECT_ROOT / "spike.db"
DEFAULT_MEMORY_SPIKE_DB_PATH = PROJECT_ROOT / "memory-spike.db"
DEFAULT_HERMES_HOME = Path(os.getenv("HERMES_HOME", str(Path.home() / ".hermes")))
DEFAULT_HERMES_PATROL_HOME = Path(os.getenv("HERMES_PATROL_HOME", str(Path.home() / ".hermes-patrol")))
DEFAULT_HERMES_CRON_JOB_ID = os.getenv("HERMES_PATROL_JOB_ID", "d27a82c0fa79")
DEFAULT_HERMES_PATROL_TRIGGER_MODE = os.getenv("HERMES_PATROL_TRIGGER_MODE", "chat")
DEFAULT_HERMES_PATROL_MAX_TURNS = _int_env("HERMES_PATROL_MAX_TURNS", 18)
DEFAULT_HERMES_PATROL_PROMPT_PATH = Path(
    os.getenv("HERMES_PATROL_PROMPT_PATH", str(PROJECT_ROOT / "hermes" / "patrol-prompt.md"))
)
