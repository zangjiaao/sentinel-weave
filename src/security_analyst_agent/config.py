from pathlib import Path
import os


PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent
FIXTURE_DIR = PROJECT_ROOT / "fixtures" / "spike"
SPIKE_MEMORY_DIR = PROJECT_ROOT / "fixtures" / "spike_memory"
DEFAULT_DB_PATH = PROJECT_ROOT / "spike.db"
DEFAULT_MEMORY_SPIKE_DB_PATH = PROJECT_ROOT / "memory-spike.db"
DEFAULT_HERMES_CRON_JOB_ID = os.getenv("HERMES_PATROL_JOB_ID", "d27a82c0fa79")
