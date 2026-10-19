"""Abstract scanner — all OS scanners + mock inherit from this."""
from abc import ABC, abstractmethod
from typing import List
from .models import WiFiNetwork

class BaseScanner(ABC):
    """WHY: OS scan commands differ (netsh vs nmcli vs airport). 
    Using one interface lets the UI call scanner.scan() without caring which OS."""
    name: str = "base"

    @abstractmethod
    def scan(self) -> List[WiFiNetwork]:
        """Return list of nearby APs. Must never throw — return [] on error."""
        ...

    def is_available(self) -> bool:
        """Check if scanner can run on this system."""
        return True
