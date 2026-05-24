import os
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.domain.schemas import RCAReport, TelemetryEvent, IncidentTimeline
from backend.workflows.state_machine import sre_analyzer_flow, IncidentState

# Initialize FastAPI application with clean OpenAPI metadata
app = FastAPI(
    title="AI-Powered SRE Root Cause Analyzer API",
    description="Observability Intelligence layer using LangGraph and Pydantic structured output models.",
    version="1.0.0"
)

# Enable CORS for Next.js frontend local connections
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    raw_payloads: List[Dict[str, Any]] = Field(
        ..., 
        description="List of raw payloads from Loki, Prometheus, Alertmanager, and GitHub."
    )
    trigger_alert_name: Optional[str] = Field(
        None, 
        description="Optional alert filter name to center timeline correlation window."
    )

class AnalyzeResponse(BaseModel):
    rca_report: Optional[RCAReport] = None
    timeline: Optional[IncidentTimeline] = None
    execution_errors: List[str] = Field(default_factory=list)

@app.get("/health", status_code=status.HTTP_200_OK)
def health_check():
    """Simple API status probe."""
    return {"status": "healthy", "service": "agentic-sre-analyzer"}

@app.post("/api/analyze", response_model=AnalyzeResponse, status_code=status.HTTP_200_OK)
async def analyze_incident(request: AnalyzeRequest):
    """
    Ingests multi-source raw logs, metrics, alerts and runs the 
    LangGraph pipeline to yield a unified causal RCA + Remediation report.
    """
    if not request.raw_payloads:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Payload stream cannot be empty."
        )
        
    # Populate the initial LangGraph thread state
    initial_state = IncidentState(
        raw_payloads=request.raw_payloads,
        trigger_alert_name=request.trigger_alert_name,
        normalized_events=[],
        compressed_events=[],
        timeline=None,
        rca_report=None,
        execution_errors=[]
    )
    
    try:
        # Run state machine synchronously
        result_state = sre_analyzer_flow.invoke(initial_state)
        
        # Check if the pipeline encountered critical execution failures
        errors = result_state.get("execution_errors", [])
        rca = result_state.get("rca_report")
        timeline = result_state.get("timeline")
        
        if not rca and errors:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"SRE Analysis pipeline failed. Errors: {errors}"
            )
            
        return AnalyzeResponse(
            rca_report=rca,
            timeline=timeline,
            execution_errors=errors
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Fatal exception inside SRE state machine: {str(e)}"
        )
