import os
import re
import google.generativeai as genai
from dotenv import load_dotenv

# Load API key
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# --- Utility Helpers ---
def clean_text(text):
    """Remove unwanted markdown and formatting artifacts."""
    text = re.sub(r"[*_|#`>-]+", "", text)
    text = re.sub(r"^\s*-{2,}\s*$", "", text, flags=re.MULTILINE)
    text = re.sub(r"\n{2,}", "\n\n", text)
    return text.strip()

def extract_severity(text):
    """Find severity classification within the report."""
    match = re.search(r"(Critical|High|Medium|Low)", text, re.IGNORECASE)
    if match:
        return match.group(1).capitalize()
    return "Unclassified"

# --- Role-based AI Model Selector ---
def select_model_for_role(role):
    """
    Selects AI model + persona based on SOC analyst level.
    """
    personas = {
        "Tier-1": "Tier-1 Analyst — performs basic triage and IOC detection.",
        "Tier-2": "Tier-2 Incident Responder — correlates IOCs, detects attack patterns, and recommends mitigations.",
        "Tier-3": "Tier-3 Senior Investigator — validates findings, assigns severity, and prepares escalation reports.",
        "Manager": "SOC Manager — final report reviewer ensuring accuracy and completeness."
    }
    return {
        "model": "gemini-2.5-flash",
        "persona": personas.get(role, "Tier-1 Analyst — default role")
    }

# --- Analyst → Auditor Loop ---
def generate_refined_report(prompt, role):
    """Analyst → Auditor loop to ensure accurate, consistent, and reliable incident reports."""

    # 1️⃣ Select the AI model/persona for the analyst’s SOC tier
    model_info = select_model_for_role(role)
    model_name = model_info["model"]
    persona = model_info["persona"]

    # 2️⃣ Analyst phase
    analyst_prompt = f"""
You are an {persona}
Analyze the following cybersecurity event input and produce a structured report.

INCIDENT INPUT:
{prompt}

Your report should include:
- Threat Summary
- Attack Vector
- Indicators of Compromise (IOCs)
- Impact Assessment
- Mitigation Recommendations
- Severity (Critical, High, Medium, Low)
If data is insufficient, write "Insufficient data".
"""
    analyst_model = genai.GenerativeModel(model_name)
    analyst_response = analyst_model.generate_content(analyst_prompt)
    analyst_report = clean_text(analyst_response.text)

    # 3️⃣ Auditor phase (internal quality control)
    auditor_prompt = f"""
You are the AI SOC Auditor. Review the analyst’s report below.

Analyst Report:
{analyst_report}

TASKS:
- Validate findings for factual accuracy.
- Replace unverifiable claims with "Needs Verification".
- Correct formatting or clarity issues.
- Keep severity classification consistent.
Return only the improved report.
"""
    auditor_model = genai.GenerativeModel(model_name)  # ⚡ Fix: was passing undefined variable
    auditor_response = auditor_model.generate_content(auditor_prompt)
    final_report = clean_text(auditor_response.text)

    # 4️⃣ Compute reliability score
    verification_tags = len(re.findall(r"Needs Verification", final_report))
    confidence = max(30, 100 - (verification_tags * 10))
    severity = extract_severity(final_report)

    metadata = {
        "confidence": confidence,
        "verification_tags": verification_tags,
        "loop_count": 2,
        "model_used": model_name,
        "analyst_role": role
    }

    return final_report, severity, metadata

