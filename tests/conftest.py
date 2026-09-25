import socket

import pytest


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Fail any test that tries to open a network connection."""

    def guard(*args, **kwargs):
        raise RuntimeError("Network access attempted in a test")

    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket.socket, "connect", guard)
