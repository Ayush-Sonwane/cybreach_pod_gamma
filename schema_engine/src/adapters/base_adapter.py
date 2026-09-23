from abc import ABC, abstractmethod
from typing import Dict, Any

try:
    from src.models.ocsf_models import OCSFAuthenticationEvent
except (ModuleNotFoundError, ImportError):
    from src.models import OCSFAuthenticationEvent


class BaseAdapter(ABC):
    """
    Abstract Base Class for all vendor adapters.
    Ensures every adapter implements the required vendor_name property
    and standard normalize() method.
    """

    @property
    @abstractmethod
    def vendor_name(self) -> str:
        """Returns the human-readable vendor name (e.g., 'IBM QRadar')."""
        pass

    @abstractmethod
    def normalize(self, raw_event: Dict[str, Any]) -> OCSFAuthenticationEvent:
        """
        Normalizes a raw vendor log event dictionary into a canonical
        OCSF Authentication Event object.
        """
        pass