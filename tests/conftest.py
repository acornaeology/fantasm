"""Shared pytest fixtures for fantasm."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest


BEEBASM_BINARY_NAME = "beebasm"


@pytest.fixture
def beebasm_filepath() -> Path:
    """Path to the ``beebasm`` executable; skips the test if it is not on PATH.

    Round-trip tests that need to assemble fantasm output should use this
    fixture rather than calling ``shutil.which`` directly, so that skipping
    behaviour is uniform across the suite.
    """
    found_filepath = shutil.which(BEEBASM_BINARY_NAME)
    if found_filepath is None:
        pytest.skip(
            f"{BEEBASM_BINARY_NAME} is not on PATH; install it to run "
            "round-trip assembly tests."
        )
    return Path(found_filepath)
