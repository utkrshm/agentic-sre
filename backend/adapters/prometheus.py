from datetime import datetime, timezone
from typing import Any, Dict, List
from backend.domain.schemas import TelemetryEvent, TelemetrySource, TelemetryType, Severity
from backend.domain.exceptions import AdapterMappingError
from backend.adapters.base import BaseProviderAdapter

class PrometheusAdapter(BaseProviderAdapter):
    """
    Adapter to parse Prometheus metric matrix/vector formats from `/api/v1/query_range` or `/api/v1/query`.
    """

    def normalize(self, raw_payload: Any) -> List[TelemetryEvent]:
        """
        Translates PromQL timeseries metrics into structured TelemetryEvents representing metric anomalies.
        """
        events = []
        if not isinstance(raw_payload, dict):
            raise AdapterMappingError("Prometheus raw payload must be a JSON dictionary object.")
            
        if raw_payload.get("status") != "success":
            return events
            
        data = raw_payload.get("data", {})
        result_type = data.get("resultType")
        
        if result_type not in ("matrix", "vector"):
            return events
            
        results = data.get("result", [])
        for metric_data in results:
            if not isinstance(metric_data, dict):
                continue
                
            metric_meta = metric_data.get("metric", {})
            metric_name = metric_meta.get("__name__", "custom_metric")
            service = metric_meta.get("job") or metric_meta.get("app") or metric_meta.get("service") or "unknown-service"
            environment = metric_meta.get("env") or metric_meta.get("environment") or "production"
            
            values = []
            if result_type == "matrix":
                # Matrix contains a list of [timestamp, value] pairs
                values = metric_data.get("values", [])
            elif result_type == "vector":
                # Vector contains a single [timestamp, value] pair under "value"
                single_val = metric_data.get("value")
                if single_val:
                    values = [single_val]
            
            for timestamp_sec, value_str in values:
                try:
                    timestamp = datetime.fromtimestamp(float(timestamp_sec), tz=timezone.utc)
                    value = float(value_str)
                except (ValueError, TypeError):
                    continue
                
                # Check metrics against deterministic SRE thresholds to identify high-value anomalies
                anomaly_detected = False
                severity = Severity.INFO
                anomaly_message = ""
                
                if metric_name == "http_requests_total" or "http_request_duration" in metric_name:
                    status = metric_meta.get("status", "")
                    handler = metric_meta.get("handler", "")
                    
                    if status.startswith("5") and value > 10.0:  # > 10 5xx errors per sec
                        anomaly_detected = True
                        severity = Severity.CRITICAL if value > 50.0 else Severity.WARNING
                        anomaly_message = f"High HTTP 5xx error rate on endpoint '{handler}' ({status}): {value:.1f} errors/sec"
                    
                    elif "duration" in metric_name and value > 2.0:  # Latency > 2 seconds
                        anomaly_detected = True
                        severity = Severity.WARNING if value < 5.0 else Severity.CRITICAL
                        anomaly_message = f"High latency detected on endpoint '{handler}': {value:.2f} seconds"

                elif "kube_pod_container_status_restarts" in metric_name:
                    pod_name = metric_meta.get("pod", "unknown-pod")
                    if value > 0:  # Restarts detected
                        anomaly_detected = True
                        severity = Severity.CRITICAL
                        anomaly_message = f"Kubernetes Pod container restart detected on pod '{pod_name}': restart count is {int(value)}"

                elif "db_connections" in metric_name or "database_connections" in metric_name:
                    if value > 90.0:  # Connection pool saturation
                        anomaly_detected = True
                        severity = Severity.CRITICAL if value >= 98.0 else Severity.WARNING
                        anomaly_message = f"Database connection pool saturation: {value:.1f}% capacity in use"
                        
                elif "cpu_usage" in metric_name or "container_cpu_usage" in metric_name:
                    if value > 90.0:
                        anomaly_detected = True
                        severity = Severity.WARNING
                        anomaly_message = f"Container CPU utilisation is high: {value:.1f}%"
                
                elif "memory_working_set" in metric_name or "jvm_memory_used" in metric_name:
                    # Let's check for standard high utilization flags if labels provide capacity limits
                    if value > 95.0:  # Assuming raw percentage
                        anomaly_detected = True
                        severity = Severity.CRITICAL
                        anomaly_message = f"Critical Memory exhaustion warning: {value:.1f}% capacity"
                
                # If we detect a threshold breach, record it as a metric anomaly event
                if anomaly_detected:
                    events.append(TelemetryEvent(
                        timestamp=timestamp,
                        source=TelemetrySource.PROMETHEUS,
                        event_type=TelemetryType.METRIC_ANOMALY,
                        severity=severity,
                        service=service,
                        environment=environment,
                        message=anomaly_message,
                        labels=metric_meta,
                        raw_details={"metric_name": metric_name, "metric_value": value, "raw_metric_labels": metric_meta}
                    ))
                
        return events
