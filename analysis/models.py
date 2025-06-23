# analysis/models.py
from django.db import models
from django.contrib.postgres.fields import JSONField
from core.models import Artefact, LogRecord

class LogicUnit(models.Model):
    EVALUATE_CHOICES = [
        ('contains', 'Contains'),
        ('regex', 'Regex'),
    ]
    label = models.CharField(max_length=255)
    pattern = models.TextField()
    evaluate = models.CharField(max_length=10, choices=EVALUATE_CHOICES)
    negate = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.label} ({self.evaluate})"


class RuleTag(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name


class Rule(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    reference = models.TextField(blank=True)
    tags = models.ManyToManyField(RuleTag, blank=True)
    logics = models.ManyToManyField(LogicUnit, blank=True)
    condition_json = models.JSONField(help_text="Boolean logic tree using logic unit IDs")
    is_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class RuleMatch(models.Model):
    rule = models.ForeignKey(Rule, on_delete=models.CASCADE, related_name="matches")
    artefact = models.ForeignKey(Artefact, on_delete=models.CASCADE)
    log_record = models.ForeignKey(LogRecord, on_delete=models.CASCADE)
    matched_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Match: {self.rule.name} on {self.artefact.name}"
