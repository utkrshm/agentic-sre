import re
from datetime import datetime
from typing import List, Dict, Tuple
from backend.domain.schemas import TelemetryEvent, TelemetryType, Severity

# Severity rank mapping for correct numerical level comparison (avoiding string alphabetical issues)
SEVERITY_RANKING = {
    Severity.DEBUG: 1,
    Severity.INFO: 2,
    Severity.WARNING: 3,
    Severity.ERROR: 4,
    Severity.CRITICAL: 5
}

class LogCompressor:
    """
    Utility to compress logs and telemetry streams by performing variable masking and
    clustering of similar events. Crucial for avoiding context window overflows.
    """

    def __init__(self):
        # Regex mappings to mask dynamic parameters within raw strings
        self.masks = [
            (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "<IP>"),
            (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
            (re.compile(r"0x[0-9a-fA-F]+"), "<HEX>"),
            (re.compile(r"\b\d+\b"), "<NUM>"),
            (re.compile(r"trace_id=[a-zA-Z0-9_\-]+"), "trace_id=<TRACE>"),
            (re.compile(r"span_id=[a-zA-Z0-9_\-]+"), "span_id=<SPAN>"),
            (re.compile(r"user_\d+"), "user_<ID>"),
            (re.compile(r"'(?:[^'\\]|\\.)*'"), "'<STR>'"),
            (re.compile(r'"(?:[^"\\]|\\.)*"'), '"<STR>"'),
        ]

    def mask_message(self, message: str) -> str:
        """
        Applies masking rules to dynamic strings to generate a structural template.
        """
        masked = message
        for pattern, replacement in self.masks:
            masked = pattern.sub(replacement, masked)
        # Collapse multiple whitespaces
        masked = re.sub(r"\s+", " ", masked).strip()
        return masked

    def compress(self, events: List[TelemetryEvent], min_severity: Severity = Severity.WARNING) -> List[TelemetryEvent]:
        """
        Deduplicates and groups similar events. Only events with severity >= min_severity are compressed,
        while Deployment and Alert events are ALWAYS kept at full fidelity without template merging.
        """
        compressed_events = []
        log_clusters: Dict[Tuple[str, str, Severity], List[TelemetryEvent]] = {}
        
        for event in events:
            # Deployment events, infrastructure changes, and alerts should NEVER be compressed or grouped
            if event.event_type in (TelemetryType.DEPLOYMENT, TelemetryType.ALERT, TelemetryType.INFRA_CHANGE):
                compressed_events.append(event)
                continue
                
            # Filter out low-severity diagnostic noise (e.g. Debug/Info logs) unless it represents metric anomalies
            if event.event_type == TelemetryType.LOG:
                event_rank = SEVERITY_RANKING.get(event.severity, 0)
                min_rank = SEVERITY_RANKING.get(min_severity, 0)
                if event_rank < min_rank:
                    continue
                
            # Generate the template key based on service, severity, and masked message template
            template = self.mask_message(event.message)
            key = (event.service, template, event.severity)
            
            if key not in log_clusters:
                log_clusters[key] = []
            log_clusters[key].append(event)
            
        # Build unified events representing each log cluster
        for (service, template, severity), cluster_events in log_clusters.items():
            first_event = cluster_events[0]
            count = len(cluster_events)
            
            if count == 1:
                # Keep exact representation if it only occurred once
                compressed_events.append(first_event)
            else:
                # Merge into a single summary event
                earliest_time = min(e.timestamp for e in cluster_events)
                latest_time = max(e.timestamp for e in cluster_events)
                
                # Gather key details from instances
                trace_ids = list(set(e.trace_id for e in cluster_events if e.trace_id))
                deployment_ids = list(set(e.deployment_id for e in cluster_events if e.deployment_id))
                
                # Create labels mapping
                merged_labels = first_event.labels.copy()
                merged_labels["occurrence_count"] = str(count)
                merged_labels["earliest_time"] = earliest_time.isoformat()
                merged_labels["latest_time"] = latest_time.isoformat()
                merged_labels["is_compressed_cluster"] = "true"
                
                summary_message = f"[Cluster x{count}] {template}"
                
                compressed_events.append(TelemetryEvent(
                    timestamp=latest_time,  # Standard: point to last occurrence
                    source=first_event.source,
                    event_type=first_event.event_type,
                    severity=severity,
                    service=service,
                    environment=first_event.environment,
                    message=summary_message,
                    trace_id=trace_ids[0] if trace_ids else None,
                    deployment_id=deployment_ids[0] if deployment_ids else None,
                    labels=merged_labels,
                    raw_details={
                        "template": template,
                        "cluster_size": count,
                        "sample_messages": [e.message for e in cluster_events[:3]]
                    }
                ))
                
        # Sort chronologically
        compressed_events.sort(key=lambda x: x.timestamp)
        return compressed_events
