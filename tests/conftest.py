from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect ~/.spiderforge and ~/.config/spiderforge into a temp dir
    so tests never touch the developer's real installation."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # Some libs cache paths at import time; reload defaults
    import importlib

    import spiderforge.config.defaults as defaults

    importlib.reload(defaults)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-browser",
        action="store_true",
        default=False,
        help="Run Playwright-dependent tests.",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "browser: requires Playwright Chromium")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-browser") or os.environ.get("SPIDERFORGE_TEST_BROWSER"):
        return
    skip = pytest.mark.skip(reason="pass --run-browser to enable")
    for item in items:
        if "browser" in item.keywords:
            item.add_marker(skip)