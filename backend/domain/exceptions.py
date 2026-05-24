class SREDomainError(Exception):
    """Base exception for all domain-level errors in the SRE application."""
    pass

class EventValidationError(SREDomainError):
    """Raised when incoming telemetry data fails domain validation schemas."""
    pass

class TimelineConstructionError(SREDomainError):
    """Raised when timeline alignment fails due to missing temporal indexes."""
    pass

class AdapterMappingError(SREDomainError):
    """Raised when a third-party payload cannot be mapped into domain telemetry."""
    pass
