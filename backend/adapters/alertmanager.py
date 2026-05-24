from datetime import datetime, timezone
from typing import Any, Dict, List
from backend.domain.schemas import TelemetryEvent, TelemetrySource, TelemetryType, Severity
from backend.domain.exceptions import AdapterMappingError
from backend.adapters.base import BaseProviderAdapter

class AlertmanagerAdapter(BaseProviderAdapter):
    """
    Adapter to parse standard Prometheus Alertmanager alert webhooks or API payloads.
    """

    def normalize(self, raw_payload: Any) -> List[TelemetryEvent]:
        """
        Translates raw Alertmanager webhook payloads into normalized TelemetryEvents.
        """
        events = []
        if not isinstance(raw_payload, dict):
            raise AdapterMappingError("Alertmanager raw payload must be a JSON dictionary object.")
            
        # Standard Alertmanager webhook format lists alerts in an "alerts" array
        alerts_list = raw_payload.get("alerts", [])
        if not alerts_list and "labels" in raw_payload:
            # Fallback if a single alert object is passed instead of list
            alerts_list = [raw_payload]
            
        for alert_data in alerts_list:
            if not isinstance(alert_data, dict):
                continue
                
            labels = alert_data.get("labels", {})
            annotations = alert_data.get("annotations", {})
            
            # Map parameters
            service = labels.get("service") or labels.get("app") or labels.get("job") or "unknown-service"
            environment = labels.get("env") or labels.get("environment") or "production"
            alertname = labels.get("alertname", "UnknownAlert")
            
            # Map severity labels
            raw_severity = labels.get("severity", "info").lower()
            severity = Severity.INFO
            if raw_severity in ("critical", "page", "fatal"):
                severity = Severity.CRITICAL
            elif raw_severity in ("warning", "warn"):
                severity = Severity.WARNING
            elif raw_severity in ("info", "low"):
                severity = Severity.INFO
                
            # Alertmanager startsAt is standard ISO8601 string
            starts_at_str = alert_data.get("startsAt")
            if starts_at_str:
                try:
                    # Clean up standard formats (zulu timezone)
                    clean_str = starts_at_str.replace("Z", "+00:00")
                    timestamp = datetime.fromisoformat(clean_str)
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
            else:
                timestamp = datetime.now(timezone.utc)
                
            status = alert_data.get("status", "firing").upper()
            summary = annotations.get("summary") or annotations.get("description") or f"Alert {alertname} {status.lower()}"
            message = f"[{status}] AlertManager Notification: {alertname} - {summary}"
            
            # Merge labels and annotations for searchability
            combined_labels = {**labels, **annotations, "alertmanager_status": status.lower()}
            
            events.append(TelemetryEvent(
                timestamp=timestamp,
                source=TelemetrySource.ALERTMANAGER,
                event_type=TelemetryType.ALERT,
                severity=severity,
                service=service,
                environment=environment,
                message=message,
                labels=combined_labels,
                raw_details=alert_data
            ))
            
        return events
