import os
import sys
import json
import argparse
from datetime import datetime
from workflows.state_machine import sre_analyzer_flow, IncidentState
from domain.schemas import Severity

def parse_args():
    parser = argparse.ArgumentParser(description="AI SRE Root Cause Analyzer CLI Demo Runner")
    parser.add_argument(
        "--scenario",
        type=str,
        choices=["bad_deployment", "db_bottleneck", "memory_leak"],
        default="bad_deployment",
        help="Target outage scenario to simulate (default: bad_deployment)"
    )
    return parser.parse_args()

def main():
    # Load .env file if it exists
    if os.path.exists(".env"):
        with open(".env") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        key, val = line.split("=", 1)
                        os.environ[key.strip()] = val.strip().strip("'").strip('"')
                    except ValueError:
                        continue

    args = parse_args()
    scenario_file = os.path.join("tests", "mock_payloads", f"{args.scenario}.json")
    
    if not os.path.exists(scenario_file):
        print(f"Error: Mock scenario file not found at {scenario_file}", file=sys.stderr)
        sys.exit(1)
        
    print("=" * 70)
    print(f"🚀 AI SRE Analyzer: Simulating Outage Scenario [{args.scenario.upper()}]")
    print("=" * 70)
    
    # Load the mock payload dataset
    try:
        with open(scenario_file, "r") as f:
            scenario_data = json.load(f)
    except Exception as e:
        print(f"Error reading mock scenario JSON: {str(e)}", file=sys.stderr)
        sys.exit(1)
        
    print(f"Description: {scenario_data.get('description', '')}\n")
    
    # Check if API Keys are configured for LLM reasoning
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    groq_key = os.environ.get("GROQ_API_KEY", "")
    
    # If the OpenAI key is actually a Groq key, override and use Groq
    if openai_key.startswith("gsk_") and not groq_key:
        groq_key = openai_key
        os.environ["GROQ_API_KEY"] = openai_key
        
    api_key_set = openai_key or groq_key
    if not api_key_set:
        print("⚠️  Warning: OPENAI_API_KEY / GROQ_API_KEY is not set in environment.")
        print("   The pipeline will run ingestion & correlation deterministically,")
        print("   but the LLM RCA & Remediation reasoning steps will be skipped.\n")
        print("   To execute the full flow, run: export OPENAI_API_KEY='your-key'\n")
        
    # Populate the initial pipeline state
    state = IncidentState(
        raw_payloads=scenario_data.get("payloads", []),
        trigger_alert_name=None,
        normalized_events=[],
        compressed_events=[],
        timeline=None,
        rca_report=None,
        execution_errors=[]
    )
    
    # Run the state machine
    try:
        # We can selectively run nodes or execute the complete flow. 
        # If no API key is present, we only execute the deterministic ingest/correlation nodes
        if not api_key_set:
            # Manually invoke state nodes to avoid LLM errors
            from workflows.state_machine import ingest_node, correlate_node
            state = ingest_node(state)
            state = correlate_node(state)
        else:
            print("⏳ Executing LangGraph analysis workflow (Ingest -> Compress -> RCA -> Remediation)...")
            state = sre_analyzer_flow.invoke(state)
    except Exception as e:
        print(f"❌ State machine execution failed: {str(e)}", file=sys.stderr)
        sys.exit(1)
        
    # 1. Print the Chronological Timeline
    print("-" * 70)
    print("📊 RECONSTRUCTED INCIDENT TIMELINE (Deterministic Output)")
    print("-" * 70)
    
    timeline = state.get("timeline")
    if not timeline or not timeline.timeline_events:
        print("No events could be reconstructed in the incident timeline.")
        if state.get("execution_errors"):
            print(f"Errors: {state.get('execution_errors')}")
        sys.exit(1)
        
    print(f"Incident Time Window: {timeline.start_time.isoformat()}  -->  {timeline.end_time.isoformat()}")
    print(f"Affected Services: {', '.join(timeline.services_affected)}")
    print("-" * 70)
    
    severity_icons = {
        Severity.DEBUG: "🔍",
        Severity.INFO: "ℹ️",
        Severity.WARNING: "⚠️",
        Severity.ERROR: "🚨",
        Severity.CRITICAL: "🔥"
    }
    
    for idx, event in enumerate(timeline.timeline_events):
        icon = severity_icons.get(event.severity, "ℹ️")
        time_str = event.timestamp.strftime("%H:%M:%S")
        source_str = event.source.value.upper()
        type_str = event.event_type.value.upper()
        
        # Display occurrence count if event represents a compressed cluster
        cluster_info = ""
        count = event.labels.get("occurrence_count")
        if count and int(count) > 1:
            cluster_info = f" [Compressed x{count}]"
            
        print(f"{idx+1:02d}. {time_str} | {icon} {event.severity.value.upper():<8} | {source_str:<12} | {event.service:<18} | {event.message}{cluster_info}")
        if event.trace_id:
            print(f"    └─ Trace ID: {event.trace_id}")
            
    print("-" * 70)
    
    # 2. Print the Root Cause Analysis Report if LLM reasoning ran
    rca = state.get("rca_report")
    if rca:
        print("\n" + "=" * 70)
        print("🧠 AI ROOT CAUSE ANALYSIS & REMEDIATION REPORT")
        print("=" * 70)
        print(f"SUMMARY: {rca.summary}\n")
        print(f"PROBABLE ROOT CAUSE: {rca.probable_root_cause}")
        print(f"ANALYSIS CONFIDENCE: {rca.confidence_score * 100:.1f}%\n")
        
        print("ALTERNATIVE HYPOTHESES:")
        for h in rca.hypotheses:
            print(f" - [{h.probability*100:3.0f}%] {h.title}")
            print(f"   Walk: {h.causal_explanation}")
            print(f"   Evidence event count: {len(h.evidence_events)}")
            
        print("\nOPERATIONAL REMEDIATION PLAN:")
        for idx, step in enumerate(rca.remediation_plan):
            print(f" {idx+1}. [ ] {step}")
            
        print("=" * 70)
    else:
        print("\n💡 Tip: To generate the AI-powered Root Cause Analysis (RCA) and")
        print("   Remediation report, set your OpenAI or Groq API key and rerun:")
        print("   export OPENAI_API_KEY='your_key'")
        print("   python main.py")
        print("=" * 70)

    # Print execution warnings or errors if they occurred
    errors = state.get("execution_errors", [])
    if errors:
        print("\n⚠️  Pipeline Warnings/Errors occurred during analysis:")
        for err in errors:
            print(f" - {err}")
        print("=" * 70)

if __name__ == "__main__":
    main()
