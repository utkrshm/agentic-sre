from abc import ABC, abstractmethod
from typing import Any, List
from backend.domain.schemas import TelemetryEvent

class BaseProviderAdapter(ABC):
    """
    Contract interface for all telemetry ingestion adapters.
    Ensures absolute decoupling of provider schemas from our domain reasoning logic.
    """
    
    @abstractmethod
    def normalize(self, raw_payload: Any) -> List[TelemetryEvent]:
        """
        Accepts raw telemetry outputs (API responses, webhooks, files) and
        normalizes them into structured, unified internal TelemetryEvent domain objects.
        """
        pass
