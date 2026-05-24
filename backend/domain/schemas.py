from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict

class TelemetrySource(str, Enum):
    LOKI = "loki"
    PROMETHEUS = "prometheus"
    ALERTMANAGER = "alertmanager"
    GITHUB = "github"
    KUBERNETES = "kubernetes"
    DATADOG = "datadog"

class TelemetryType(str, Enum):
    LOG = "log"
    METRIC_ANOMALY = "metric_anomaly"
    ALERT = "alert"
    DEPLOYMENT = "deployment"
    INFRA_CHANGE = "infra_change"

class Severity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class TelemetryEvent(BaseModel):
    """
    Normalized core event model representing a single telemetry point in time.
    All adapters must map provider-specific data into this structure.
    """
    model_config = ConfigDict(populate_by_name=True)

    event_id: UUID = Field(default_factory=uuid4, description="Unique internal event identifier")
    timestamp: datetime = Field(..., description="Timestamp of the event (UTC)")
    source: TelemetrySource = Field(..., description="Telemetry source system")
    event_type: TelemetryType = Field(..., description="The type classification of telemetry")
    severity: Severity = Field(Severity.INFO, description="Normalized severity level")
    service: str = Field(..., description="Name of the affected service (e.g. auth-service)")
    message: str = Field(..., description="The primary human-readable payload/message")
    
    # Metadata for advanced correlation & grouping
    environment: str = Field("production", description="Deploy environment (production, staging, dev)")
    trace_id: Optional[str] = Field(None, description="Distributed tracing identifier for trace correlation")
    span_id: Optional[str] = Field(None, description="Distributed tracing span identifier")
    deployment_id: Optional[str] = Field(None, description="Deployment version associated with this event")
    
    # Structured key-value pairs (e.g. kubernetes pod name, http status code, region)
    labels: Dict[str, str] = Field(default_factory=dict, description="Metadata tags/labels from the provider")
    raw_details: Dict[str, Any] = Field(default_factory=dict, description="Escaped exact raw source payload fields")

class IncidentTimeline(BaseModel):
    """
    An ordered sequence of events that represent the story of an incident.
    """
    model_config = ConfigDict(populate_by_name=True)

    incident_id: UUID = Field(default_factory=uuid4)
    start_time: datetime = Field(..., description="Timeline collection window start time")
    end_time: datetime = Field(..., description="Timeline collection window end time")
    services_affected: List[str] = Field(default_factory=list, description="List of services involved in the incident window")
    timeline_events: List[TelemetryEvent] = Field(default_factory=list, description="Chronological sequence of telemetry events")

class RCAHypothesis(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    title: str = Field(..., description="Short descriptive title of the hypothesis")
    probability: float = Field(..., description="Confidence score between 0.0 and 1.0")
    causal_explanation: str = Field(..., description="Deep architectural explanation of how this cause led to the failure")
    evidence_events: List[UUID] = Field(..., description="References to the normalized event_ids that support this hypothesis")

class RCAReport(BaseModel):
    """
    Structured outcome of the AI Root Cause Analysis agent.
    """
    model_config = ConfigDict(populate_by_name=True)

    incident_id: UUID = Field(..., description="Associated incident identifier")
    summary: str = Field(..., description="Executive summary of the incident")
    probable_root_cause: str = Field(..., description="The highly probable trigger and root failure mechanism")
    confidence_score: float = Field(..., description="Aggregated system confidence score (0.0 to 1.0)")
    hypotheses: List[RCAHypothesis] = Field(default_factory=list, description="Ranked list of alternative failure scenarios")
    remediation_plan: List[str] = Field(default_factory=list, description="Chronological suggestions for SRE mitigation")
