# analysis/views.py

from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.http import StreamingHttpResponse
from django.views import View
from django.views.generic import TemplateView, ListView
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from core.models import Artefact, Incident
from .models import *
from django.utils import timezone
import ast
from django.db.models import Count
from time import sleep
@method_decorator(login_required, name='dispatch')
class UnifiedDashboardView(TemplateView):
    template_name = "analysis/dashboard.html"

    def get_context_data(self, **kwargs):
        user = self.request.user

        artefacts = Artefact.objects.filter(assigned_to=user).select_related('incident')
        incidents = Incident.objects.filter(responders=user)
        recent_matches = RuleMatch.objects.filter(
            artefact__assigned_to=user
        ).select_related('rule', 'log_record', 'artefact').order_by('-matched_at')[:10]

        # Optional: store/resume recent artefact analysis
        last_artefact_id = self.request.session.get("last_analysed_artefact_id")
        resume_artefact = None
        if last_artefact_id:
            resume_artefact = Artefact.objects.filter(id=last_artefact_id, assigned_to=user).first()

        return {
            "artefacts": artefacts,
            "incidents": incidents,
            "recent_matches": recent_matches,
            "resume_artefact": resume_artefact,
        }

class AnalysisStartView(ListView):
    template_name = "analysis/start_analysis.html"
    context_object_name = "artefacts"

    def get_queryset(self):
        return (
            Artefact.objects.filter(assigned_to=self.request.user)
            .select_related('incident')
            .order_by('-uploaded_at')
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['incidents'] = (
            Incident.objects.filter(responders=self.request.user)
            .annotate(artefact_count=Count('artefacts'))
            .order_by('-created_at')
        )
        context['rules'] = (
            Rule.objects.filter(is_enabled=True)
            .prefetch_related("tags", "logics")
        )
        context['tags'] = RuleTag.objects.all().order_by('name')

        return context


@login_required
def run_analysis(request):
    artefact_ids = request.POST.getlist("artefact_ids")
    rule_ids = request.POST.get("rule_ids", "").split(",")

    artefacts = Artefact.objects.filter(id__in=artefact_ids, assigned_to=request.user).prefetch_related("records")
    rules = Rule.objects.filter(id__in=rule_ids, is_enabled=True).prefetch_related("logics", "tags")

    def stream():
        for artefact in artefacts:
            current_artefact = artefact.name
            for record in artefact.records.all():
                current_record = record.record_index
                for rule in rules:
                    # Yield the current analysis step
                    yield f"Checking {current_artefact} - Record #{current_record} - Rule: {rule.name}\n"
                    
                    # Evaluate logics
                    logic_results = {}
                    for i, logic in enumerate(rule.logics.all(), 1):
                        alias = f"L{i}"
                        result = logic.evaluate(record.content)
                        logic_results[alias] = result
                    
                    # Check if rule matches
                    try:
                        expr = rule.boolean_expression
                        for alias, result in logic_results.items():
                            expr = expr.replace(alias, str(result))
                        passed = ast.literal_eval(expr)
                    except Exception:
                        passed = False
                    
                    if passed:
                        # Create match record
                        match = RuleMatch.objects.create(
                            rule=rule,
                            artefact=artefact,
                            log_record=record,
                            matched_at=timezone.now()
                        )
                        
                        # Save logic evaluations
                        for i, logic in enumerate(rule.logics.all(), 1):
                            LogicEvaluation.objects.create(
                                rule_match=match,
                                logic_unit=logic,
                                passed=logic_results[f"L{i}"]
                        )

    return StreamingHttpResponse(stream(), content_type='text/plain')


@method_decorator(login_required, name='dispatch')
class ArtefactAnalysisResultView(TemplateView):
    template_name = "analysis/artefact_result.html"

    def get_context_data(self, **kwargs):
        artefact = get_object_or_404(Artefact, id=self.kwargs['pk'], assigned_to=self.request.user)
        matches = RuleMatch.objects.filter(artefact=artefact).select_related('rule', 'log_record').prefetch_related('logic_evaluations', 'rule__tags', 'rule__mitre_techniques')
        return {
            "artefact": artefact,
            "matches": matches,
        }


@method_decorator(login_required, name='dispatch')
class IncidentAnalysisDashboardView(TemplateView):
    template_name = "analysis/incident_result.html"

    def get_context_data(self, **kwargs):
        incidents = Incident.objects.filter(responders=self.request.user).prefetch_related('artefacts__rule_matches')
        return {
            "incidents": incidents
        }
