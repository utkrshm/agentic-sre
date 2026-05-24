from typing import List, Dict, Any, Optional, TypedDict
from langgraph.graph import StateGraph, START, END

from backend.domain.schemas import TelemetryEvent, IncidentTimeline, RCAReport
from backend.domain.exceptions import SREDomainError
from backend.adapters.loki import LokiAdapter
from backend.adapters.prometheus import PrometheusAdapter
from backend.adapters.alertmanager import AlertmanagerAdapter
from backend.adapters.github import GitHubActionsAdapter
from backend.pipeline.compression import LogCompressor
from backend.pipeline.correlation import TimelineCorrelator
from backend.agents.rca_agent import RCAAgent
from backend.agents.remediation_agent import RemediationAgent

class IncidentState(TypedDict):
    """
    Maintains state across our deterministic pipelines and reasoning agents.
    """
    raw_payloads: List[Dict[str, Any]]
    trigger_alert_name: Optional[str]
    normalized_events: List[TelemetryEvent]
    compressed_events: List[TelemetryEvent]
    timeline: Optional[IncidentTimeline]
    rca_report: Optional[RCAReport]
    execution_errors: List[str]

# 1. Ingest & Normalize Node (Deterministic)
def ingest_node(state: IncidentState) -> Dict[str, Any]:
    normalized_events = []
    errors = []
    
    loki_adapter = LokiAdapter()
    prom_adapter = PrometheusAdapter()
    am_adapter = AlertmanagerAdapter()
    github_adapter = GitHubActionsAdapter()
    
    for item in state.get("raw_payloads", []):
        source = item.get("source", "").lower()
        raw_data = item.get("data")
        
        if not raw_data:
            continue
            
        try:
            if source == "loki":
                events = loki_adapter.normalize(raw_data)
            elif source == "prometheus":
                events = prom_adapter.normalize(raw_data)
            elif source == "alertmanager":
                events = am_adapter.normalize(raw_data)
            elif source == "github":
                events = github_adapter.normalize(raw_data)
            else:
                continue
                
            normalized_events.extend(events)
        except Exception as e:
            errors.append(f"Ingest error for source '{source}': {str(e)}")
            
    # Sort chronologically
    normalized_events.sort(key=lambda x: x.timestamp)
    
    return {
        "normalized_events": normalized_events,
        "execution_errors": state.get("execution_errors", []) + errors
    }

# 2. Compress & Correlate Node (Deterministic)
def correlate_node(state: IncidentState) -> Dict[str, Any]:
    events = state.get("normalized_events", [])
    errors = []
    compressed_events = []
    timeline = None
    
    if not events:
        return {
            "execution_errors": state.get("execution_errors", []) + ["No telemetry events available to correlate."]
        }
        
    try:
        # Compress / de-duplicate logs
        compressor = LogCompressor()
        compressed_events = compressor.compress(events)
        
        # Build timeline
        correlator = TimelineCorrelator()
        timeline = correlator.build_timeline(
            events=compressed_events,
            trigger_alert_name=state.get("trigger_alert_name")
        )
    except Exception as e:
        errors.append(f"Correlation / timeline alignment failed: {str(e)}")
        
    return {
        "compressed_events": compressed_events,
        "timeline": timeline,
        "execution_errors": state.get("execution_errors", []) + errors
    }

# 3. Core RCA Agent Node (LLM-Driven)
def rca_agent_node(state: IncidentState) -> Dict[str, Any]:
    timeline = state.get("timeline")
    errors = []
    rca_report = None
    
    if not timeline or not timeline.timeline_events:
        return {
            "execution_errors": state.get("execution_errors", []) + ["Timeline is empty. Skipping RCA reasoning."]
        }
        
    try:
        rca_agent = RCAAgent()
        rca_report = rca_agent.analyze(timeline)
    except Exception as e:
        errors.append(f"RCA Agent reasoning failed: {str(e)}")
        
    return {
        "rca_report": rca_report,
        "execution_errors": state.get("execution_errors", []) + errors
    }

# 4. Remediation Agent Node (LLM-Driven)
def remediation_node(state: IncidentState) -> Dict[str, Any]:
    rca_report = state.get("rca_report")
    errors = []
    
    if not rca_report:
        return {
            "execution_errors": state.get("execution_errors", []) + ["RCA report is missing. Skipping remediation plans."]
        }
        
    try:
        remediation_agent = RemediationAgent()
        plan = remediation_agent.generate_plan(rca_report)
        # Update the structured report with the operational steps
        rca_report.remediation_plan = plan
    except Exception as e:
        errors.append(f"Remediation agent planning failed: {str(e)}")
        
    return {
        "rca_report": rca_report,
        "execution_errors": state.get("execution_errors", []) + errors
    }


# Assemble and compile the state graph
workflow = StateGraph(IncidentState)

# Define nodes
workflow.add_node("ingest", ingest_node)
workflow.add_node("correlate", correlate_node)
workflow.add_node("rca", rca_agent_node)
workflow.add_node("remediation", remediation_node)

# Set up transitions
workflow.add_edge(START, "ingest")
workflow.add_edge("ingest", "correlate")
workflow.add_edge("correlate", "rca")
workflow.add_edge("rca", "remediation")
workflow.add_edge("remediation", END)

# Compile active graph application
sre_analyzer_flow = workflow.compile()
