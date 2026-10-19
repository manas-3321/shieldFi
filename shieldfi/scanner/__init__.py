"""Scanner package — OS-specific + mock."""
from .models import WiFiNetwork
from .base import BaseScanner

__all__ = ["WiFiNetwork", "BaseScanner"]
