import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from backend.domain.schemas import TelemetryEvent, TelemetrySource, TelemetryType, Severity
from backend.domain.exceptions import AdapterMappingError
from backend.adapters.base import BaseProviderAdapter

class LokiAdapter(BaseProviderAdapter):
    """
    Adapter to parse Grafana Loki JSON output from `/loki/api/v1/query_range` or `/loki/api/v1/query`.
    """
    
    def __init__(self):
        # Compiled patterns to extract tracing context and identifiers from log strings
        self.trace_pattern = re.compile(r"trace_id=([a-zA-Z0-9_\-]+)")
        self.span_pattern = re.compile(r"span_id=([a-zA-Z0-9_\-]+)")
        self.deploy_pattern = re.compile(r"deployment_id=([a-zA-Z0-9_\-\.]+)|deploy_id=([a-zA-Z0-9_\-\.]+)|v([0-9]+\.[0-9]+\.[0-9]+)")

    def normalize(self, raw_payload: Any) -> List[TelemetryEvent]:
        """
        Translates raw Loki API JSON data into unified TelemetryEvents.
        """
        events = []
        if not isinstance(raw_payload, dict):
            raise AdapterMappingError("Loki raw payload must be a JSON dictionary object.")
            
        if raw_payload.get("status") != "success":
            return events
            
        data = raw_payload.get("data", {})
        result_type = data.get("resultType")
        
        # Loki results can be "streams" (most common for log queries) or "matrix"/"vector" for metrics-over-logs
        if result_type != "streams":
            return events
            
        streams = data.get("result", [])
        for stream_data in streams:
            if not isinstance(stream_data, dict):
                continue
                
            labels = stream_data.get("stream", {})
            
            # Extract standard SRE tags from labels
            service = labels.get("app") or labels.get("service") or labels.get("job") or "unknown-service"
            environment = labels.get("env") or labels.get("environment") or "production"
            
            # Map log levels to standard SRE severities
            raw_level = labels.get("level") or labels.get("severity") or "info"
            severity = self._map_severity(raw_level)
            
            values = stream_data.get("values", [])
            for value_pair in values:
                if not isinstance(value_pair, list) or len(value_pair) < 2:
                    continue
                
                timestamp_ns_str, log_message = value_pair[0], value_pair[1]
                
                try:
                    # Loki log timestamp is UNIX timestamp in nanoseconds as string
                    timestamp = datetime.fromtimestamp(int(timestamp_ns_str) / 1e9, tz=timezone.utc)
                except (ValueError, TypeError) as e:
                    # Fallback to current time if parsing fails
                    timestamp = datetime.now(timezone.utc)
                
                # Check log message content for inline log level overrides (e.g. "ERROR: DB issue")
                msg_lower = log_message.lower()
                calculated_severity = severity
                if "error" in msg_lower or "exception" in msg_lower or "failed" in msg_lower:
                    if calculated_severity.value < Severity.ERROR.value:
                        calculated_severity = Severity.ERROR
                elif "critical" in msg_lower or "fatal" in msg_lower:
                    calculated_severity = Severity.CRITICAL
                elif "warn" in msg_lower:
                    if calculated_severity.value < Severity.WARNING.value:
                        calculated_severity = Severity.WARNING

                # Extract distributed tracing information if available
                trace_id = self._extract_regex(self.trace_pattern, log_message)
                span_id = self._extract_regex(self.span_pattern, log_message)
                
                # Extract deployment identifier
                deploy_match = self.deploy_pattern.search(log_message)
                deployment_id = None
                if deploy_match:
                    # Return the first matching group that is not None
                    deployment_id = next((g for g in deploy_match.groups() if g is not None), None)
                
                events.append(TelemetryEvent(
                    timestamp=timestamp,
                    source=TelemetrySource.LOKI,
                    event_type=TelemetryType.LOG,
                    severity=calculated_severity,
                    service=service,
                    environment=environment,
                    message=log_message,
                    trace_id=trace_id,
                    span_id=span_id,
                    deployment_id=deployment_id,
                    labels=labels,
                    raw_details={"stream_labels": labels, "raw_timestamp_ns": timestamp_ns_str}
                ))
                
        return events

    def _map_severity(self, raw_level: str) -> Severity:
        lvl = raw_level.lower()
        if lvl in ("debug", "trace"):
            return Severity.DEBUG
        elif lvl in ("info", "notice"):
            return Severity.INFO
        elif lvl in ("warn", "warning"):
            return Severity.WARNING
        elif lvl in ("error", "err"):
            return Severity.ERROR
        elif lvl in ("crit", "critical", "fatal", "emerg", "alert"):
            return Severity.CRITICAL
        return Severity.INFO

    def _extract_regex(self, pattern: re.Pattern, text: str) -> Optional[str]:
        match = pattern.search(text)
        return match.group(1) if match else None
