from datetime import datetime, timedelta, timezone
from typing import List, Optional
from backend.domain.schemas import TelemetryEvent, IncidentTimeline, TelemetryType, Severity
from backend.domain.exceptions import TimelineConstructionError

class TimelineCorrelator:
    """
    Groups and sequences normalized, compressed telemetry events chronologically to reconstruct
    the exact narrative timeline of an SRE incident.
    """

    def build_timeline(
        self, 
        events: List[TelemetryEvent], 
        trigger_alert_name: Optional[str] = None,
        pre_incident_window_mins: int = 15,
        post_incident_window_mins: int = 5
    ) -> IncidentTimeline:
        """
        Filters and groups events into an IncidentTimeline based on temporal alert windows.
        """
        if not events:
            raise TimelineConstructionError("Cannot build timeline from empty telemetry event list.")
            
        # 1. Identify the Incident Trigger Time (T0)
        t0: Optional[datetime] = None
        
        # Look for the trigger alert event
        for event in events:
            if event.event_type == TelemetryType.ALERT and event.severity in (Severity.WARNING, Severity.CRITICAL):
                if not trigger_alert_name or trigger_alert_name.lower() in event.message.lower():
                    t0 = event.timestamp
                    break
                    
        # Fallback if no explicit alert is found: use the timestamp of the highest-severity event
        if not t0:
            critical_events = [e for e in events if e.severity == Severity.CRITICAL]
            if critical_events:
                # Sort critical events to get the earliest one
                critical_events.sort(key=lambda x: x.timestamp)
                t0 = critical_events[0].timestamp
            else:
                # Fallback to the very last event in the series
                all_sorted = sorted(events, key=lambda x: x.timestamp)
                t0 = all_sorted[-1].timestamp
                
        # 2. Define the temporal slicing window [T0 - pre_window, T0 + post_window]
        start_window = t0 - timedelta(minutes=pre_incident_window_mins)
        end_window = t0 + timedelta(minutes=post_incident_window_mins)
        
        # 3. Filter events within the window and sort chronologically
        timeline_events = [
            event for event in events 
            if start_window <= event.timestamp <= end_window
        ]
        
        # Sort chronologically (earliest first)
        timeline_events.sort(key=lambda x: x.timestamp)
        
        if not timeline_events:
            # Fallback: if slicing left us empty, keep the entire raw event stream sorted
            timeline_events = sorted(events, key=lambda x: x.timestamp)
            start_window = timeline_events[0].timestamp
            end_window = timeline_events[-1].timestamp
            
        # 4. Extract unique services affected during this window
        services_affected = list(set(
            event.service for event in timeline_events 
            if event.service and event.service != "unknown-service"
        ))
        
        return IncidentTimeline(
            start_time=start_window,
            end_time=end_window,
            services_affected=services_affected,
            timeline_events=timeline_events
        )
