import os
from typing import List, Optional
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.output_parsers import StrOutputParser
from domain.schemas import RCAReport
from domain.exceptions import SREDomainError
from agents.prompts import REMEDIATION_SYSTEM_PROMPT, REMEDIATION_USER_TEMPLATE

class RemediationAgent:
    """
    SRE Agent that takes a Root Cause Analysis (RCA) report and generates a prioritized, 
    highly detailed list of technical recovery steps and runbook actions.
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
            return ChatGroq(model=model, temperature=0.2)
        elif openai_key:
            from langchain_openai import ChatOpenAI
            model = os.environ.get("OPENAI_MODEL_NAME", "gpt-4o-mini")
            return ChatOpenAI(model=model, temperature=0.2)
        else:
            # Fallback when testing locally or running mock environments
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model="gpt-4o-mini", temperature=0.2)

    def generate_plan(self, rca_report: RCAReport) -> List[str]:
        """
        Generates step-by-step mitigation instructions based on an RCA report.
        """
        # Format hypotheses for SRE runbook lookup context
        hypotheses_lines = []
        for h in rca_report.hypotheses:
            hypotheses_lines.append(f"- {h.title} (Probability: {h.probability*100:.0f}%)\n  Explanation: {h.causal_explanation}")
        hypotheses_str = "\n".join(hypotheses_lines)

        prompt = ChatPromptTemplate.from_messages([
            ("system", REMEDIATION_SYSTEM_PROMPT),
            ("user", REMEDIATION_USER_TEMPLATE)
        ])

        chain = prompt | self.llm | StrOutputParser()

        try:
            raw_output: str = chain.invoke({
                "root_cause": rca_report.probable_root_cause,
                "confidence": rca_report.confidence_score,
                "summary": rca_report.summary,
                "hypotheses_str": hypotheses_str
            })

            # Parse bulleted lines into clean list elements
            remediation_steps = []
            for line in raw_output.split("\n"):
                clean_line = line.strip()
                if not clean_line:
                    continue
                # Remove common markdown bullet symbols
                if clean_line.startswith(("-", "*", "1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.")):
                    # Remove bullet character and trim
                    stripped = re_strip_bullet(clean_line)
                    if stripped:
                        remediation_steps.append(stripped)
                else:
                    remediation_steps.append(clean_line)
                    
            if not remediation_steps:
                remediation_steps = [raw_output]
                
            return remediation_steps
            
        except Exception as e:
            raise SREDomainError(f"Remediation Agent failed to generate recovery plans. Error: {str(e)}")

def re_strip_bullet(text: str) -> str:
    """Helper to strip markdown bullet points from lines."""
    import re
    # Remove things like "- ", "* ", "1. ", "10. "
    res = re.sub(r"^(?:\-\s*|\*\s*|\d+\.\s*)", "", text)
    return res.strip()
