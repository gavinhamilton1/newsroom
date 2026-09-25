import socket

import pytest


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Fail any test that tries to open a network connection."""

    def guard(*args, **kwargs):
        raise RuntimeError("Network access attempted in a test")

    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket.socket, "connect", guard)


def assert_sdk_accepts(method_name: str, kwargs: dict) -> None:
    """Fail if the installed anthropic SDK would reject these keyword arguments.

    Fake clients call this so tests catch signature changes (anthropic 1.x removed
    `temperature` from messages.create, which a permissive fake silently accepted)."""
    import inspect

    from anthropic.resources.messages import Messages

    inspect.signature(getattr(Messages, method_name)).bind(None, **kwargs)
