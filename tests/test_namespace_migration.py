from pathlib import Path

import zog.root_control as root_control


def test_canonical_namespace_and_version():
    assert root_control.__name__ == "zog.root_control"
    assert root_control.__version__ == "0.1.0"


def test_namespace_package_layout():
    root = Path(__file__).resolve().parents[1]
    assert (root / "src" / "zog" / "root_control" / "__init__.py").is_file()
    assert not (root / "src" / "zog" / "__init__.py").exists()
    assert not (root / "root_control").exists()
