import sys
from pathlib import Path
import pytest

if __name__ == "__main__":
    backend_dir = Path(__file__).resolve().parent
    repo_root = backend_dir.parent
    sys.path.insert(0, str(repo_root))
    sys.path.insert(0, str(backend_dir))
    sys.path.insert(0, str(repo_root / "intelligence"))
    sys.path.insert(0, str(repo_root / "intelligence" / "certificate_analyzer" / "src"))
    sys.path.insert(0, str(repo_root / "intelligence" / "certificate_dataset" / "src"))
    sys.path.insert(0, str(repo_root / "intelligence" / "web_security_analysis"))
    sys.path.insert(0, str(repo_root / "intelligence" / "web_security_analysis" / "analyzer"))
    tests_dir = backend_dir / "app" / "tests"
    sys.exit(pytest.main(["-v", str(tests_dir)]))
