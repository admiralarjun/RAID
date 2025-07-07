
# ai.py
import json
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone

from core.models import *
from analysis.models import *
from google import genai
from google.genai import types

from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from google import genai
from .gemini_schema import AILogicGroup
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json, os
from google import genai
from pydantic import BaseModel
from django.views import View


client = genai.Client(api_key=os.environ.get('AI_API_KEY'))


class Highlight(BaseModel):
    record_index: int = Field(..., description="Index of the record in the artefact")
    log_index: str = Field(..., description="Unique identifier for the log entry")
    excerpt: str = Field(..., description="Relevant excerpt from the record")
    reason: str = Field(..., description="Explanation for why this highlight is important")

class Reference(BaseModel):
    rule_match_id: int = Field(..., description="ID of the matched rule")
    rule_name: str = Field(..., description="Name of the matched rule")
    log_index: str = Field(..., description="Unique identifier for the log entry")
    record_index: int = Field(..., description="Index of the record in the artefact")
    mitre_techniques: List[str] = Field(..., description="List of MITRE ATT&CK technique IDs relevant to this reference")

class AIAnalysisOutput(BaseModel):
    summary: str = Field(..., description="Concise summary of key findings")
    narrative: str = Field(..., description="Detailed narrative explaining the analysis and findings")
    highlights: List[Highlight] = Field(..., description="List of critical events or excerpts with context and reasoning")
    references: List[Reference] = Field(..., description="References to rule matches and MITRE techniques relevant to the findings")
    recommendations: List[str] = Field(..., description="Actionable recommendations for next steps or remediation")

# --- Prompt Templates ---
PROMPTS: Dict[str, str] = {
    'evtx': '''
You are a forensic incident responder examining Windows Event Logs from "{name} (type: {atype})".
Review each event for indicators of malicious or anomalous behavior, uncover patterns of compromise or policy violations, and explain how these events map to attacker tactics and techniques.
Highlight the most critical events, anomalous sequences, and potential threat paths. Conclude with concise recommendations for next steps in investigation and mitigation.
''',
    'pcap': '''
You are a network security analyst dissecting the packet capture "{name} (type: {atype})".
Inspect network flows, protocol exchanges, and payloads to detect intrusion attempts, data exfiltration, or lateral movement.
Identify suspicious sessions, protocol anomalies, or malicious content and explain their relevance to the incident.
Finish with clear, actionable recommendations for containment, further packet analysis, or network defenses.
''',
    'generic': '''
You are an experienced incident responder analyzing the artefact "{name}" (type: {atype}).
Interpret the data to spot signs of malicious activity, contextualize noteworthy entries, and reconstruct likely adversary actions.
Emphasize critical findings and unusual patterns, then provide concise next steps for triage, containment, and remediation.
'''
}

@require_POST
@csrf_exempt
def ai_artefact_analysis(request, artefact_id):
    artefact = get_object_or_404(Artefact, id=artefact_id)
    atype = artefact.artefact_type.lower() or 'generic'

    # Build context
    records = list(artefact.records.values('record_index', 'content'))
    matches = []
    for rm in RuleMatch.objects.filter(artefact=artefact):
        matches.append({
            'rule_match_id': rm.id,
            'rule_name': rm.rule.name,
            'record_index': rm.log_record.record_index,
            'log_index': rm.log_record.id,
            'mitre_techniques': [t.technique_id for t in rm.rule.mitre_techniques.all()]
        })
    logic_map = {}
    for le in LogicEvaluation.objects.filter(rule_match__in=[m['rule_match_id'] for m in matches]):
        logic_map.setdefault(le.rule_match_id, []).append({'logic': le.logic_unit.name, 'passed': le.passed})

    # Select prompt and format
    template = PROMPTS.get(atype, PROMPTS['generic'])
    prompt = template.format(
        name=artefact.name,
        atype=artefact.artefact_type,
        records=json.dumps(records),
        matches=json.dumps(matches),
        logic=json.dumps(logic_map)
    )

    print(f"AI Analysis Prompt for {artefact.name} (type: {artefact.artefact_type}):\n{prompt}\n")

    # Call LLM
    ai_response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config={
            "response_mime_type": "application/json",
            "response_schema": AIAnalysisOutput,
        },
    )

    # Parsing the response
    ai_response: AIAnalysisOutput = ai_response.parsed

    print(f"AI Analysis Response for {artefact.name} (type: {artefact.artefact_type}):\n{type(ai_response)}\n{'='*50}\n{ai_response}")

    # Persist, overwrite
    AIAnalysisResult.objects.filter(artefact=artefact).delete()

    result = AIAnalysisResult.objects.create(
        artefact=artefact,
        artefact_type=artefact.artefact_type,
        summary=ai_response.summary,
        narrative=ai_response.narrative,
        highlights=[h.model_dump() for h in ai_response.highlights],
        references=[r.model_dump() for r in ai_response.references],
        prompt_used=prompt,
        raw_response=ai_response.model_dump(),
        generated_at=timezone.now()
    )

    return JsonResponse({'result_id': result.id, **ai_response.model_dump()})




class ArtefactSummary(BaseModel):
    name: str = Field(..., description="Name of the artefact")
    artefact_type: str = Field(..., description="Type of the artefact")
    summary: str = Field(..., description="Concise summary of the artefact analysis")
    highlights: List[int] = Field(..., description="List of record indices for key highlights")
    recommendations: List[str] = Field(..., description="Actionable recommendations for this artefact")

class Hypothesis(BaseModel):
    description: str = Field(..., description="Description of the attack hypothesis")
    artefacts: List[str] = Field(..., description="Names of artefacts supporting this hypothesis")
    mitre_techniques: List[str] = Field(..., description="Relevant MITRE ATT&CK technique IDs")

class Action(BaseModel):
    hypothesis_index: int = Field(..., description="Index of the related hypothesis")
    description: str = Field(..., description="Description of the recommended action")

class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    icon: str  # Example: "fa fa-file-code"

class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: Optional[str] = None

class IncidentGraph(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]

class IncidentAIOutput(BaseModel):
    incident_summary: str = Field(..., description="Cohesive overview of the incident")
    artefacts: List[ArtefactSummary] = Field(..., description="Individual artefact analyses")
    hypotheses: List[Hypothesis] = Field(..., description="Attack hypotheses with lineage")
    actions: List[Action] = Field(..., description="Next steps tied to each hypothesis")
    workflows: List[str] = Field(..., description="Adaptive playbook recommendations")
    gaps: List[str] = Field(..., description="Data or analysis gaps identified")
    graph: IncidentGraph = Field(..., description="Graph representation of incident relationships")



def ai_incident_analysis(request, incident_id):
    incident = get_object_or_404(Incident, incident_id=incident_id)

    artefact_summaries = []
    all_mitre = set()

    for arte in incident.artefacts.all():
        latest = arte.ai_results.order_by('-generated_at').first()
        if not latest:
            continue
        artefact_summaries.append({
            "name": arte.name,
            "artefact_type": arte.artefact_type,
            "summary": latest.summary.replace("\n", " ")[:200],
            "highlights": [h["record_index"] for h in latest.highlights],
            "recommendations": latest.raw_response.get("recommendations", [])
        })
        for ref in latest.references:
            all_mitre.update(ref.get("mitre_techniques", []))

    artefact_summaries = [ArtefactSummary(**a) for a in artefact_summaries]

    # Build enhanced ATHAFI-structured prompt
    prompt = f"""
    You are acting as an ATHAFI-guided cyber threat analyst tasked with synthesizing artefact-level insights into actionable incident understanding. Take a structured, hypothesis-driven approach using strong analytical reasoning.

    Incident Context:
    - Incident ID: {incident.incident_id}
    - Title: {incident.title}

    Artefact Summaries:
    (Summarize findings for each artefact. Use this data to draw connections, assess evidence strength, and reason about possible attack paths.)
    """
    for a in artefact_summaries:
        prompt += f"- Artefact: {a.name} ({a.artefact_type})\n"
        prompt += f"  Summary: {a.summary}\n"
        prompt += f"  Key Highlights (record indices): {a.highlights}\n"
        prompt += f"  Recommended Next Steps: {a.recommendations}\n"

    prompt += f"""
    Detected MITRE Techniques:
    {sorted(all_mitre)}

    Analysis Tasks:
    You must produce a structured JSON response according to the IncidentAIOutput schema. Your answer should demonstrate:
    - Cross-artefact reasoning: correlate findings across artefacts to build coherent hypotheses.
    - Analytical rigor: base each hypothesis on available evidence, but clearly state assumptions or uncertainties.
    - Operational clarity: propose practical next steps as actions, with each action clearly tied to its supporting hypothesis.

    Output the following fields:

    1. **incident_summary:** A concise summary of the incident’s likely scope, impact, and observed behaviours. Ground your summary in the artefact evidence and MITRE mappings.

    2. **hypotheses:** Create 5 plausible hypotheses about the attacker’s objectives, tactics, or stages of compromise. Each hypothesis should include:
    - A clear description.
    - The artefacts supporting this hypothesis (list artefact names).
    - Mapped MITRE techniques (ATT&CK IDs) supporting your reasoning.

    3. **actions:** For each hypothesis, list recommended actions. Specify whether the action is investigative, containment-related, or requires further analysis. Link each action to the corresponding hypothesis using its index.

    4. **adaptive_workflows:** Suggest workflows or response steps that adapt to evolving findings. Consider evidence gaps, pivot points, and defensive priorities.

    5. **evidence_gaps:** Identify areas where evidence is missing, ambiguous, or requires deeper investigation. Suggest where to search for additional artefacts or telemetry.

    Use clear, structured reasoning. Be concise but complete.
    Return JSON adhering to the IncidentAIOutput schema.
    """

    resp = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config={
            "response_mime_type": "application/json",
            "response_schema": IncidentAIOutput,
        },
    )
    incident_output: IncidentAIOutput = resp.parsed
    print(f"AI Incident Analysis Response for {incident.incident_id}:\n{incident_output}")

    # Persist results
    IncidentAnalysisResult.objects.filter(incident=incident).delete()
    ira = IncidentAnalysisResult.objects.create(
        incident=incident,
        summary=incident_output.incident_summary,
        prompt_used=prompt,
        raw_response={**resp.model_dump(), "graph": incident_output.graph.model_dump()},
        generated_at=timezone.now(),
    )

    # Create hypotheses and actions
    for idx, hyp in enumerate(incident_output.hypotheses):
        obj = IncidentHypothesis.objects.create(
            analysis=ira,
            description=hyp.description,
            artefacts=hyp.artefacts,
            mitre_techniques=hyp.mitre_techniques
        )
        for action in incident_output.actions:
            if action.hypothesis_index == idx:
                IncidentAction.objects.create(
                    hypothesis=obj,
                    description=action.description,
                    status='todo'
                )

    # Generate correlation graph
    incident_graph = generate_incident_correlation_graph(
        incident=incident,
        artefacts=artefact_summaries,
        hypotheses=incident_output.hypotheses,
        actions=incident_output.actions,
        summary=incident_output.incident_summary,
    )

    # Update incident_output with the graph
    incident_output.graph = incident_graph

    return JsonResponse({"incident_ai_result_id": ira.id, **incident_output.model_dump()})



def generate_incident_correlation_graph(
    incident: Incident,
    artefacts: List[ArtefactSummary],
    hypotheses: List[Hypothesis],
    actions: List[Action],
    summary: str,
) -> IncidentGraph:
    """
    Builds a context-rich prompt and generates the graph using LLM.
    """

    # Construct the input text for the LLM
    prompt = f"""
    You are generating a cyber incident graph describing relationships between artefacts, attack hypotheses, and recommended actions.
    
    Incident Details:
    - Incident ID: {incident.incident_id}
    - Title: {incident.title}
    - Summary: {summary}

    Artefacts:
    """
    for art in artefacts:
        prompt += f"- {art.name} ({art.artefact_type}): {art.summary}\n"

    prompt += "\nHypotheses:\n"
    for idx, hyp in enumerate(hypotheses):
        prompt += f"- Hypothesis #{idx + 1}: {hyp.description}\n"
        prompt += f"  Supporting Artefacts: {', '.join(hyp.artefacts)}\n"
        prompt += f"  MITRE Techniques: {', '.join(hyp.mitre_techniques)}\n"

    prompt += "\nActions:\n"
    for act in actions:
        prompt += f"- Action: {act.description} (Linked to Hypothesis #{act.hypothesis_index})\n"

    prompt += """

    Generate a directed graph capturing these relationships.
    - Nodes: Artefacts, Hypotheses, and Actions.
    - Edges: Show which artefacts support which hypotheses, and which actions address each hypothesis.
    - Each node should have:
      - A unique ID
      - A short label
      - A type (Artefact / Hypothesis / Action)
      - A suitable icon (font-awesome class like 'fa fa-file', 'fa fa-lightbulb', 'fa fa-wrench').

    Generate this graph structure as JSON compatible with the IncidentGraph schema.
    """

    # LLM Call
    resp = genai.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config={"response_mime_type": "application/json"},
    )

    # Parse response
    graph_data = json.loads(resp.text)
    graph = IncidentGraph(**graph_data)

    return graph