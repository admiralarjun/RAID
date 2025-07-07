# models/analysis.py (or analysis/models.py)
from django.db import models
from core.models import Artefact, LogRecord, Incident
import re
from django.utils import timezone

class LogicUnit(models.Model):
    EVALUATION_METHODS = [
        ('contains', 'Contains'),
        ('regex', 'Regex'),
    ]

    name = models.CharField(max_length=100)
    pattern = models.TextField()
    method = models.CharField(max_length=10, choices=EVALUATION_METHODS)
    negate = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({'NOT ' if self.negate else ''}{self.method} '{self.pattern}')"

    def evaluate(self, log_line: str) -> bool:
        try:
            result = False
            if self.method == 'contains':
                result = self.pattern in log_line
            elif self.method == 'regex':
                result = re.search(self.pattern, log_line) is not None
            return not result if self.negate else result
        except Exception:
            return False


class RuleTag(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name


class MitreTechnique(models.Model):
    technique_id = models.CharField(max_length=20, unique=True)  # e.g., T1059
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.technique_id} - {self.name}"


class Rule(models.Model):
    name = models.CharField(max_length=150)
    description = models.TextField(blank=True)
    is_enabled = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    logics = models.ManyToManyField(LogicUnit, related_name="rules", blank=True)
    boolean_expression = models.TextField(
        help_text="Use logic aliases like: (L1 and L2) or not L3. L1 refers to the 1st logic in the list."
    )

    tags = models.ManyToManyField(RuleTag, blank=True)
    mitre_techniques = models.ManyToManyField(MitreTechnique, blank=True)

    def __str__(self):
        return self.name


class RuleMatch(models.Model):
    rule = models.ForeignKey(Rule, on_delete=models.CASCADE, related_name="matches")
    artefact = models.ForeignKey(Artefact, on_delete=models.CASCADE, related_name="rule_matches")
    log_record = models.ForeignKey(LogRecord, on_delete=models.CASCADE, related_name="rule_matches")
    matched_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.rule.name} matched on {self.artefact.name} - Record {self.log_record.record_index}"


class LogicEvaluation(models.Model):
    rule_match = models.ForeignKey(RuleMatch, on_delete=models.CASCADE, related_name="logic_evaluations")
    logic_unit = models.ForeignKey(LogicUnit, on_delete=models.CASCADE)
    passed = models.BooleanField()

    def __str__(self):
        return f"{self.logic_unit.name} = {'✅' if self.passed else '❌'}"

class AIAnalysisResult(models.Model):
    artefact = models.ForeignKey(Artefact, on_delete=models.CASCADE, related_name='ai_results')
    artefact_type = models.CharField(max_length=50)
    generated_at = models.DateTimeField(auto_now_add=True)
    summary = models.TextField()
    narrative = models.TextField()
    highlights = models.JSONField(default=list)   # List of {record_index, excerpt, reason}
    references = models.JSONField(default=list)   # List of {rule_match_id, rule_name, record_index, mitre_techniques}
    prompt_used = models.TextField()              # The exact prompt sent to the AI
    raw_response = models.JSONField(default=dict) # Full AI response JSON

    def __str__(self):
        return f"AIAnalysisResult({self.artefact.name}@{self.generated_at:%Y-%m-%d %H:%M:%S})"
    


class IncidentAnalysisResult(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='ai_incident_results')
    generated_at = models.DateTimeField(default=timezone.now)
    summary = models.TextField()
    prompt_used = models.TextField()
    raw_response = models.JSONField(default=dict)
    graph = models.JSONField(default=dict, null=True, blank=True)

    def __str__(self):
        return f"IncidentAnalysisResult({self.incident.incident_id}@{self.generated_at:%Y-%m-%d %H:%M:%S})"

class IncidentHypothesis(models.Model):
    analysis = models.ForeignKey(IncidentAnalysisResult, on_delete=models.CASCADE, related_name='hypotheses')
    description = models.TextField()
    artefacts = models.JSONField(default=list)         # list of artefact names
    mitre_techniques = models.JSONField(default=list)  # list of ATT&CK IDs
    
class IncidentAction(models.Model):
    hypothesis = models.ForeignKey(IncidentHypothesis, on_delete=models.CASCADE, related_name='actions')
    description = models.TextField()
    status = models.CharField(max_length=20, choices=[
        ('todo','To Do'), ('in_progress','In Progress'), ('done','Done')], default='todo')