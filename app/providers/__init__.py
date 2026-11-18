"""Plugin-based provider registry.

New VPN providers can be registered dynamically via register_provider() or
by subclassing Provider without modifying the extraction engine.
"""
from __future__ import annotations

from typing import Type

from .base import Provider
from .windscribe import Windscribe
from .importers import Surfshark, ProtonVPN


class ProviderRegistry:
    """Extensible registry of VPN provider plugins."""

    def __init__(self) -> None:
        self._classes: dict[str, Type[Provider]] = {}

    def register(self, provider_cls: Type[Provider]) -> None:
        if not isinstance(provider_cls, type) or not issubclass(provider_cls, Provider):
            raise TypeError('Provider plugin must be a subclass of Provider.')
        key = getattr(provider_cls, 'key', '').strip().lower()
        if not key:
            raise ValueError('Provider plugin must define a non-empty key.')
        self._classes[key] = provider_cls

    def unregister(self, key: str) -> None:
        self._classes.pop(key.strip().lower(), None)

    def keys(self) -> list[str]:
        return list(self._classes.keys())

    def instantiate_all(self) -> dict[str, Provider]:
        return {key: cls() for key, cls in self._classes.items()}

    def get(self, key: str) -> Provider:
        cls = self._classes.get(key.strip().lower())
        if cls is None:
            raise KeyError(f'Unknown provider plugin: {key}')
        return cls()


DEFAULT_REGISTRY = ProviderRegistry()
for _builtin in (Windscribe, Surfshark, ProtonVPN):
    DEFAULT_REGISTRY.register(_builtin)


def register_provider(provider_cls: Type[Provider]) -> None:
    """Register an additional Provider plugin class at runtime."""
    DEFAULT_REGISTRY.register(provider_cls)


def unregister_provider(key: str) -> None:
    """Remove a registered Provider plugin class."""
    DEFAULT_REGISTRY.unregister(key)


def load_providers() -> dict[str, Provider]:
    """Instantiate all registered provider plugins."""
    return DEFAULT_REGISTRY.instantiate_all()
