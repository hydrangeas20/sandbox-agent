"""docs/GUARANTEES.md must name only code and tests that exist."""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "GUARANTEES.md"


def _defined(path: Path) -> set[str]:
    """Top-level functions/classes and Class.method names defined in a module."""
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    names.add(f"{node.name}.{item.name}")
    return names


def _test_names() -> set[str]:
    names: set[str] = set()
    for path in (ROOT / "tests").glob("test_*.py"):
        names |= set(re.findall(r"^def (test_\w+)", path.read_text(), flags=re.M))
    return names


def test_every_enforcing_symbol_exists() -> None:
    refs = re.findall(r"`([\w/.]+\.py)::([\w.]+)`", DOC.read_text())
    assert len(refs) >= 40
    missing = [
        f"{path}::{symbol}"
        for path, symbol in refs
        if not (ROOT / path).is_file() or symbol not in _defined(ROOT / path)
    ]
    assert missing == []


def test_every_regression_test_exists() -> None:
    cited = set(re.findall(r"`(test_\w+)`", DOC.read_text()))
    assert len(cited) >= 60
    assert sorted(cited - _test_names()) == []
