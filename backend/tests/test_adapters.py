import os
import json
from datetime import datetime
from backend.domain.schemas import TelemetryType, Severity, TelemetrySource
from backend.adapters.loki import LokiAdapter
from backend.adapters.prometheus import PrometheusAdapter
from backend.adapters.alertmanager import AlertmanagerAdapter
from backend.adapters.github import GitHubActionsAdapter

def test_loki_adapter():
    adapter = LokiAdapter()
    scenario_path = os.path.join("tests", "mock_payloads", "bad_deployment.json")
    with open(scenario_path, "r") as f:
        data = json.load(f)
        
    loki_payload = next(item["data"] for item in data["payloads"] if item["source"] == "loki")
    events = adapter.normalize(loki_payload)
    
    assert len(events) > 0
    for e in events:
        assert e.source == TelemetrySource.LOKI
        assert e.event_type == TelemetryType.LOG
        assert e.service == "auth-service"
        assert isinstance(e.timestamp, datetime)
        if "trace_id=" in e.message:
            assert e.trace_id == "t89410a8b" or e.trace_id == "t89410a8c"

def test_prometheus_adapter():
    adapter = PrometheusAdapter()
    scenario_path = os.path.join("tests", "mock_payloads", "bad_deployment.json")
    with open(scenario_path, "r") as f:
        data = json.load(f)
        
    prom_payload = next(item["data"] for item in data["payloads"] if item["source"] == "prometheus")
    events = adapter.normalize(prom_payload)
    
    # We should get connection threshold warnings or error anomalies
    assert len(events) > 0
    for e in events:
        assert e.source == TelemetrySource.PROMETHEUS
        assert e.event_type == TelemetryType.METRIC_ANOMALY
        assert e.severity in (Severity.WARNING, Severity.CRITICAL)

def test_alertmanager_adapter():
    adapter = AlertmanagerAdapter()
    scenario_path = os.path.join("tests", "mock_payloads", "bad_deployment.json")
    with open(scenario_path, "r") as f:
        data = json.load(f)
        
    am_payload = next(item["data"] for item in data["payloads"] if item["source"] == "alertmanager")
    events = adapter.normalize(am_payload)
    
    assert len(events) == 1
    event = events[0]
    assert event.source == TelemetrySource.ALERTMANAGER
    assert event.event_type == TelemetryType.ALERT
    assert event.severity == Severity.CRITICAL
    assert event.service == "postgres-db"
    assert "PostgresConnectionsExhausted" in event.message

if __name__ == "__main__":
    print("🧪 Running Ingestion Adapter Unit Tests...")
    try:
        test_loki_adapter()
        print("  ✅ LokiAdapter normalization verified.")
        test_prometheus_adapter()
        print("  ✅ PrometheusAdapter thresholds verified.")
        test_alertmanager_adapter()
        print("  ✅ Alertmanager webhook structures verified.")
        print("🎉 All ingestion unit tests passed successfully!")
    except AssertionError as e:
        print(f"❌ Test verification failed: AssertionError", file=sys.stderr)
        raise e
