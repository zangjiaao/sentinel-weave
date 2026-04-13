from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent
FIXTURE_DIR = PROJECT_ROOT / "fixtures" / "spike"
DEFAULT_DB_PATH = PROJECT_ROOT / "spike.db"

