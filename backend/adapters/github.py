from datetime import datetime, timezone
from typing import Any, Dict, List
from backend.domain.schemas import TelemetryEvent, TelemetrySource, TelemetryType, Severity
from backend.domain.exceptions import AdapterMappingError
from backend.adapters.base import BaseProviderAdapter

class GitHubActionsAdapter(BaseProviderAdapter):
    """
    Adapter to parse GitHub Action / Webhook deployment and workflow_run events.
    """

    def normalize(self, raw_payload: Any) -> List[TelemetryEvent]:
        """
        Translates raw GitHub/GitLab deployment JSON event data into TelemetryEvents.
        """
        events = []
        if not isinstance(raw_payload, dict):
            raise AdapterMappingError("GitHub raw payload must be a JSON dictionary object.")
            
        # Check standard GitHub deployment event webhook signature
        if "deployment" in raw_payload:
            deploy_data = raw_payload.get("deployment", {})
            repo_data = raw_payload.get("repository", {})
            
            service = repo_data.get("name") or repo_data.get("full_name") or "unknown-service"
            environment = deploy_data.get("environment", "production")
            ref = deploy_data.get("ref", "main")
            sha = deploy_data.get("sha", "")[:8]
            deploy_id = str(deploy_data.get("id", ""))
            
            created_at_str = deploy_data.get("created_at")
            if created_at_str:
                try:
                    clean_str = created_at_str.replace("Z", "+00:00")
                    timestamp = datetime.fromisoformat(clean_str)
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
            else:
                timestamp = datetime.now(timezone.utc)
                
            message = f"Deployment Triggered: Service '{service}' version '{sha}' ({ref}) deployed to {environment}."
            
            events.append(TelemetryEvent(
                timestamp=timestamp,
                source=TelemetrySource.GITHUB,
                event_type=TelemetryType.DEPLOYMENT,
                severity=Severity.INFO,
                service=service,
                environment=environment,
                message=message,
                deployment_id=deploy_id,
                labels={
                    "sha": sha,
                    "ref": ref,
                    "deploy_id": deploy_id,
                    "sender": raw_payload.get("sender", {}).get("login", "unknown")
                },
                raw_details=raw_payload
            ))
            
        # Alternate parsing: direct pipeline build event status
        elif "workflow_run" in raw_payload:
            wf_run = raw_payload.get("workflow_run", {})
            repo_data = raw_payload.get("repository", {})
            
            service = repo_data.get("name") or "unknown-service"
            environment = "production"  # Standard assumption
            sha = wf_run.get("head_sha", "")[:8]
            conclusion = wf_run.get("conclusion") or "running"
            event_name = wf_run.get("event", "push")
            
            created_at_str = wf_run.get("created_at") or wf_run.get("updated_at")
            if created_at_str:
                try:
                    clean_str = created_at_str.replace("Z", "+00:00")
                    timestamp = datetime.fromisoformat(clean_str)
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
            else:
                timestamp = datetime.now(timezone.utc)
                
            message = f"CI Pipeline finished: {wf_run.get('name', 'build')} concluded as '{conclusion}' for '{service}' (SHA: {sha}, Event: {event_name})."
            
            # Record failed pipelines as critical warning events
            severity = Severity.WARNING if conclusion == "failure" else Severity.INFO
            
            events.append(TelemetryEvent(
                timestamp=timestamp,
                source=TelemetrySource.GITHUB,
                event_type=TelemetryType.DEPLOYMENT if conclusion == "success" else TelemetryType.INFRA_CHANGE,
                severity=severity,
                service=service,
                environment=environment,
                message=message,
                deployment_id=str(wf_run.get("id", "")),
                labels={
                    "sha": sha,
                    "conclusion": conclusion,
                    "run_id": str(wf_run.get("id")),
                    "workflow_name": wf_run.get("name", "")
                },
                raw_details=raw_payload
            ))
            
        return events
