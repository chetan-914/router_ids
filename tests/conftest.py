"""Pytest configuration and fixtures."""

import sys
from pathlib import Path

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def sample_pcap_path():
    """Path to sample pcap file."""
    return str(Path(__file__).parent.parent / "examples" / "sample_pcap.pcap")
