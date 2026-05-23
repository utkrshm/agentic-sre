import os
from typing import Optional
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.language_models.chat_models import BaseChatModel
from domain.schemas import IncidentTimeline, RCAReport
from domain.exceptions import SREDomainError
from agents.prompts import RCA_SYSTEM_PROMPT, RCA_USER_TEMPLATE

class RCAAgent:
    """
    SRE Agent that performs root cause analysis on normalized, compressed timelines.
    Utilizes LLM structured outputs to map raw reasoning to strongly typed Pydantic models.
    """

    def __init__(self, llm: Optional[BaseChatModel] = None):
        self.llm = llm or self._initialize_llm()

    def _initialize_llm(self) -> BaseChatModel:
        """
        Dynamically initializes the appropriate LLM provider depending on environment flags.
        Handles dynamic detection of Groq keys mapped to OPENAI_API_KEY.
        """
        openai_key = os.environ.get("OPENAI_API_KEY", "")
        groq_key = os.environ.get("GROQ_API_KEY", "")
        
        # If the OpenAI key is actually a Groq key, override and use Groq
        if openai_key.startswith("gsk_") and not groq_key:
            groq_key = openai_key
            os.environ["GROQ_API_KEY"] = openai_key
            
        if groq_key:
            from langchain_groq import ChatGroq
            model = os.environ.get("GROQ_MODEL_NAME", "llama-3.3-70b-versatile")
            return ChatGroq(model=model, temperature=0.1)
        elif openai_key:
            from langchain_openai import ChatOpenAI
            model = os.environ.get("OPENAI_MODEL_NAME", "gpt-4o-mini")
            return ChatOpenAI(model=model, temperature=0.1)
        else:
            # Fallback when testing locally or running mock environments
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model="gpt-4o-mini", temperature=0.1)

    def analyze(self, timeline: IncidentTimeline) -> RCAReport:
        """
        Processes an IncidentTimeline and returns a validated RCAReport.
        """
        # Format the chronological events into a clear textual timeline for LLM consumption
        timeline_lines = []
        for idx, event in enumerate(timeline.timeline_events):
            time_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            source_tag = event.source.value.upper()
            type_tag = event.event_type.value.upper()
            sev_tag = event.severity.value.upper()
            
            trace_tag = f" | trace_id={event.trace_id}" if event.trace_id else ""
            deploy_tag = f" | deploy_id={event.deployment_id}" if event.deployment_id else ""
            
            line = f"[{idx+1}] {time_str} | {source_tag} | {type_tag} | {sev_tag} | Service: {event.service} {trace_tag}{deploy_tag}\n    Message: {event.message}\n    Event_ID: {event.event_id}"
            timeline_events_metadata = []
            if event.labels:
                labels_str = ", ".join(f"{k}={v}" for k, v in event.labels.items())
                line += f"\n    Labels: {{{labels_str}}}"
            
            timeline_lines.append(line)
            
        timeline_str = "\n\n".join(timeline_lines)
        services_str = ", ".join(timeline.services_affected)
        
        # Build prompt messages
        prompt = ChatPromptTemplate.from_messages([
            ("system", RCA_SYSTEM_PROMPT),
            ("user", RCA_USER_TEMPLATE)
        ])
        
        # Bind the Pydantic schema for structured JSON output
        structured_llm = self.llm.with_structured_output(RCAReport)
        
        # Chain prompt and execution
        chain = prompt | structured_llm
        
        try:
            report: RCAReport = chain.invoke({
                "incident_id": str(timeline.incident_id),
                "start_time": timeline.start_time.isoformat(),
                "end_time": timeline.end_time.isoformat(),
                "services": services_str,
                "timeline_str": timeline_str
            })
            return report
        except Exception as e:
            raise SREDomainError(f"RCA Agent reasoning failed to generate structured report. Error: {str(e)}")
