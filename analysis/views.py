# analysis/views.py

from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.http import StreamingHttpResponse
from django.views import View
from django.views.generic import TemplateView, ListView
from django.shortcuts import render, redirect, get_object_or_404
from core.models import Artefact, Incident
from .models import *
from django.utils import timezone
import ast
from django.db.models import Count
from django.db import transaction
from collections import defaultdict
from django.db.models import Q, Prefetch
from django.core.paginator import Paginator
from django.urls import reverse
import requests, threading
from .ai import generate_rules_from_internet_intel
@method_decorator(login_required, name='dispatch')
class UnifiedDashboardView(TemplateView):
    template_name = "analysis/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        now = timezone.now()

        ### Artefact Base Query (fetch IDs first, avoid overfetching)
        artefact_qs = Artefact.objects.filter(assigned_to=user).select_related('incident')

        # Annotate once
        artefacts = artefact_qs.annotate(
            record_count=Count('records', distinct=True),
            match_count=Count('rule_matches', distinct=True),
            recent_matches=Count(
                'rule_matches',
                filter=Q(rule_matches__matched_at__gte=now - timedelta(days=7)),
                distinct=True
            )
        ).order_by('-uploaded_at')

        # Dashboard-level stats (combine into one queryset)
        total_artefacts = artefacts.count()

        total_matches_qs = RuleMatch.objects.filter(artefact__assigned_to=user)
        total_matches = total_matches_qs.count()
        matches_today = total_matches_qs.filter(matched_at__date=now.date()).count()
        high_activity_artefacts = artefacts.filter(recent_matches__gt=5).count()

        ### Incidents
        incidents = Incident.objects.filter(responders=user).prefetch_related('responders').annotate(
            artefact_count=Count('artefacts', distinct=True),
            total_matches=Count('artefacts__rule_matches', distinct=True)
        ).order_by('-created_at')

        active_incidents = incidents.count()

        ### Resume Analysis
        resume_artefact = None
        last_artefact_id = self.request.session.get("last_analysed_artefact_id")
        if last_artefact_id:
            resume_artefact = artefact_qs.filter(id=last_artefact_id).first()

        ### Top Rules
        top_rules = Rule.objects.filter(
            matches__artefact__assigned_to=user,
            is_enabled=True
        ).annotate(
            match_count=Count('matches', distinct=True)
        ).prefetch_related('tags').order_by('-match_count')[:5]

        ### Final Context
        context.update({
            'artefacts': artefacts,
            'incidents': incidents,
            'resume_artefact': resume_artefact,
            'stats': {
                'total_artefacts': total_artefacts,
                'active_incidents': active_incidents,
                'total_matches': total_matches,
                'matches_today': matches_today,
                'high_activity_artefacts': high_activity_artefacts,
            },
            'top_rules': top_rules,
        })

        return context

class AnalysisStartView(ListView):
    template_name = "analysis/start_analysis.html"
    context_object_name = "artefacts"

    def get_queryset(self):
        return (
            Artefact.objects.filter(assigned_to=self.request.user)
            .select_related('incident')
            .prefetch_related('records')
            .order_by('-uploaded_at')
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Get incidents with artefact count for the current user
        context['incidents'] = (
            Incident.objects.filter(responders=self.request.user)
            .annotate(artefact_count=Count('artefacts', filter=Q(artefacts__assigned_to=self.request.user)))
            .filter(artefact_count__gt=0)  # Only show incidents that have artefacts assigned to this user
            .order_by('-created_at')
        )
        
        # Get enabled rules with their related data
        context['rules'] = (
            Rule.objects.filter(is_enabled=True)
            .prefetch_related("tags", "logics")
            .order_by('name')
        )
        
        # Get all rule tags for filtering
        context['tags'] = RuleTag.objects.all().order_by('name')

        return context


def safe_boolean_eval(expression: str, context: dict) -> bool:
    """
    Safely evaluates a boolean expression using ast parsing.
    Allows only basic boolean operations.
    """
    try:
        expr_ast = ast.parse(expression, mode='eval')

        # Only allow safe node types
        for node in ast.walk(expr_ast):
            if not isinstance(node, (ast.Expression, ast.BoolOp, ast.UnaryOp, ast.Name,
                                     ast.Load, ast.And, ast.Or, ast.Not,
                                     ast.Constant, ast.NameConstant)):
                raise ValueError(f"Unsafe expression element: {type(node).__name__}")

        # Evaluate in the provided context
        compiled = compile(expr_ast, "<string>", "eval")
        return bool(eval(compiled, {"__builtins__": {}}, context))

    except Exception as e:
        raise ValueError(f"Expression evaluation failed: {e}")


@login_required
def run_analysis(request):
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    
    artefact_ids = request.POST.getlist("artefact_ids")
    rule_ids_str = request.POST.get("rule_ids", "")
    
    # Parse rule IDs, handling empty strings and filtering out invalid IDs
    rule_ids = [rid.strip() for rid in rule_ids_str.split(",") if rid.strip()]
    
    if not artefact_ids:
        return JsonResponse({'error': 'No artefacts selected'}, status=400)
    
    if not rule_ids:
        return JsonResponse({'error': 'No rules selected'}, status=400)

    # Get artefacts assigned to the current user
    artefacts = Artefact.objects.filter(
        id__in=artefact_ids,
        assigned_to=request.user
    ).prefetch_related("incident", "records")

    if not artefacts.exists():
        return JsonResponse({'error': 'No valid artefacts found'}, status=400)

    # Get enabled rules
    rules = Rule.objects.filter(
        id__in=rule_ids,
        is_enabled=True
    ).prefetch_related("logics", "tags")

    if not rules.exists():
        return JsonResponse({'error': 'No valid rules found'}, status=400)

    def stream():
        yield '<p class="text-primary"><i class="fas fa-play-circle"></i> Starting rule-based analysis...</p>\n'
        yield f'<p class="text-info"><i class="fas fa-info-circle"></i> Analyzing {artefacts.count()} artefact(s) with {rules.count()} rule(s)</p>\n'

        total_artefacts = artefacts.count()
        total_matches = 0
        
        try:
            with transaction.atomic():
                for artefact_index, artefact in enumerate(artefacts, start=1):
                    yield f'<p class="text-info"><i class="fas fa-file-alt"></i> Artefact [{artefact_index}/{total_artefacts}]: <strong>{artefact.name}</strong></p>\n'

                    records = list(artefact.records.all())
                    if not records:
                        yield '<p class="text-warning"><i class="fas fa-exclamation-circle"></i> No records found for this artefact.</p>\n'
                        continue

                    total_records = len(records)
                    yield f'<p class="text-secondary"><i class="fas fa-database"></i> Processing {total_records} record(s)</p>\n'
                    
                    artefact_matches = 0
                    for record_index, record in enumerate(records, start=1):
                        if record_index % 10 == 0 or record_index == total_records:
                            yield f'<p class="text-secondary"><i class="fas fa-database"></i> Record [{record_index}/{total_records}] #{record.record_index}</p>\n'

                        for rule_index, rule in enumerate(rules, start=1):
                            if record_index == 1:  # Only show rule info for first record
                                yield f'<p class="text-secondary"><i class="fas fa-cogs"></i> Applying Rule [{rule_index}/{rules.count()}]: <strong>{rule.name}</strong></p>\n'

                            logic_results = {}
                            logics = list(rule.logics.all())
                            
                            # Evaluate each logic
                            for i, logic in enumerate(logics, 1):
                                alias = f"L{i}"
                                try:
                                    logic_results[alias] = logic.evaluate(record.content)
                                    if record_index == 1:  # Only show detailed logic results for first record
                                        result_icon = "fas fa-check-circle" if logic_results[alias] else "fas fa-times-circle"
                                        result_class = "text-success" if logic_results[alias] else "text-danger"
                                        yield f'<p class="{result_class}"><i class="{result_icon}"></i> Logic "{logic.name}": {logic_results[alias]}</p>\n'
                                except Exception as e:
                                    if record_index == 1:
                                        yield f'<p class="text-danger"><i class="fas fa-bug"></i> Error in Logic "{logic.name}": {e}</p>\n'
                                    logic_results[alias] = False

                            # Evaluate boolean expression
                            try:
                                passed = safe_boolean_eval(rule.boolean_expression, logic_results)
                            except Exception as e:
                                if record_index == 1:
                                    yield f'<p class="text-danger"><i class="fas fa-exclamation-triangle"></i> Error evaluating boolean expression: {e}</p>\n'
                                passed = False

                            # Create match if rule passed
                            if passed:
                                match, created = RuleMatch.objects.get_or_create(
                                    rule=rule,
                                    artefact=artefact,
                                    log_record=record,
                                    defaults={'matched_at': timezone.now()}
                                )
                                if created:
                                    artefact_matches += 1
                                    total_matches += 1
                                    yield f'<p class="text-success"><i class="fas fa-check-circle"></i> Match found for record #{record.record_index} (ID: {match.id})</p>\n'
                                    
                                    # Create logic evaluations
                                    LogicEvaluation.objects.bulk_create([
                                        LogicEvaluation(
                                            rule_match=match,
                                            logic_unit=lg,
                                            passed=logic_results.get(f"L{idx}", False)
                                        ) for idx, lg in enumerate(logics, 1)
                                    ])

                    if artefact_matches > 0:
                        yield f'<p class="text-success"><i class="fas fa-trophy"></i> Found {artefact_matches} match(es) for artefact: {artefact.name}</p>\n'
                    else:
                        yield f'<p class="text-muted"><i class="fas fa-times-circle"></i> No matches found for artefact: {artefact.name}</p>\n'

            yield f'<p class="text-primary"><i class="fas fa-check"></i> Rule-based analysis complete. Total matches: {total_matches}</p>\n'

        except Exception as e:
            yield f'<p class="text-danger"><i class="fas fa-exclamation-triangle"></i> Analysis error: {str(e)}</p>\n'
            return

        # Trigger artefact-level AI analysis
        yield '<p class="text-primary"><i class="fas fa-robot"></i> Triggering AI analysis for artefacts...</p>\n'
        artefact_links = []
        
        for artefact_idx, artefact in enumerate(artefacts, start=1):
            try:
                url = request.build_absolute_uri(reverse('analysis:ai_artefact_analysis', args=[artefact.id]))
                resp = requests.post(url, timeout=90)
                if resp.ok:
                    artefact_result_url = request.build_absolute_uri(reverse('analysis:artefact_result', args=[artefact.id]))
                    artefact_links.append(f'<a href="{artefact_result_url}" target="_blank" class="btn btn-sm btn-outline-primary me-1">{artefact.name}</a>')
                    yield f'<p class="text-success"><i class="fas fa-robot"></i> Artefact [{artefact_idx}/{total_artefacts}]: AI analysis completed for <strong>{artefact.name}</strong></p>\n'
                else:
                    yield f'<p class="text-danger"><i class="fas fa-times-circle"></i> Artefact [{artefact_idx}/{total_artefacts}]: AI analysis failed for {artefact.name}: {resp.status_code}</p>\n'
            except Exception as e:
                yield f'<p class="text-danger"><i class="fas fa-exclamation-circle"></i> Artefact [{artefact_idx}/{total_artefacts}]: AI request error for {artefact.name}: {e}</p>\n'

        # Add result buttons to the modal
        if artefact_links:
            yield f'<script>document.getElementById("results-section").classList.remove("d-none"); document.getElementById("result-buttons").innerHTML = "{" ".join(artefact_links)}";</script>\n'

        # Trigger incident-level AI analysis
        incident_id = None
        if artefacts.exists() and artefacts.first().incident:
            incident_id = str(artefacts.first().incident.incident_id)

        if incident_id:
            yield '<p class="text-primary"><i class="fas fa-robot"></i> Triggering incident-level AI analysis...</p>\n'
            try:
                url_inc = request.build_absolute_uri(reverse('analysis:ai_incident_analysis', args=[incident_id]))
                resp = requests.post(url_inc, timeout=300)
                if resp.ok:
                    incident_result_url = request.build_absolute_uri(reverse('core:incident_detail', args=[incident_id]))
                    yield f'<p class="text-success"><i class="fas fa-check-circle"></i> Incident-level AI analysis completed. <a href="{incident_result_url}" target="_blank" class="btn btn-sm btn-outline-success">View Incident</a></p>\n'
                else:
                    yield f'<p class="text-danger"><i class="fas fa-times-circle"></i> Incident-level AI failed: {resp.status_code}</p>\n'
            except Exception as e:
                yield f'<p class="text-danger"><i class="fas fa-exclamation-circle"></i> Incident-level AI error: {e}</p>\n'
        else:
            yield '<p class="text-warning"><i class="fas fa-exclamation-triangle"></i> No incident found for the artefacts. Skipping incident AI analysis.</p>\n'

        yield '<p class="text-success"><i class="fas fa-flag-checkered"></i> Full analysis complete.</p>\n'

    return StreamingHttpResponse(stream(), content_type='text/html')

@method_decorator(login_required, name='dispatch')
class ArtefactAnalysisResultView(TemplateView):
    template_name = "analysis/artefact_result.html"
    paginate_by = 20

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        artefact = get_object_or_404(Artefact, id=self.kwargs['pk'], assigned_to=self.request.user)
        
        # Get filter parameters from request
        search_query = self.request.GET.get('search', '').strip()
        status_filter = self.request.GET.get('status', '')
        tag_filter = self.request.GET.get('tag', '')
        mitre_filter = self.request.GET.get('mitre', '')
        expand_all = self.request.GET.get('expand_all', False)
        
        # Build base queryset with optimized queries
        matches_qs = RuleMatch.objects.filter(
            artefact=artefact
        ).select_related(
            'rule', 'log_record'
        ).prefetch_related(
            Prefetch('logic_evaluations', 
                    queryset=LogicEvaluation.objects.select_related('logic_unit')),
            'rule__tags',
            'rule__mitre_techniques'
        )
        
        # Apply filters server-side
        if search_query:
            matches_qs = matches_qs.filter(
                Q(rule__name__icontains=search_query) |
                Q(rule__description__icontains=search_query) |
                Q(log_record__content__icontains=search_query)
            )
        
        if tag_filter:
            matches_qs = matches_qs.filter(rule__tags__name=tag_filter)
            
        if mitre_filter:
            matches_qs = matches_qs.filter(rule__mitre_techniques__technique_id=mitre_filter)
        
        # Filter by status (passed/failed)
        if status_filter == 'passed':
            # Only matches where all logic evaluations passed
            matches_qs = matches_qs.annotate(
                failed_evals=Count('logic_evaluations', filter=Q(logic_evaluations__passed=False))
            ).filter(failed_evals=0)
        elif status_filter == 'failed':
            # Matches with at least one failed evaluation
            matches_qs = matches_qs.filter(logic_evaluations__passed=False).distinct()
        
        matches_qs = matches_qs.order_by('log_record__record_index', 'matched_at')
        
        # Group matches by log record
        grouped_matches = defaultdict(list)
        status_counts = {'passed': 0, 'failed': 0}
        unique_rules = set()
        
        for match in matches_qs:
            grouped_matches[match.log_record].append(match)
            unique_rules.add(match.rule.id)
            
            # Determine if match passed or failed
            evaluations = list(match.logic_evaluations.all())
            all_passed = all(eval.passed for eval in evaluations) if evaluations else False
            status_counts['passed' if all_passed else 'failed'] += 1
        
        # Convert to sorted list for template
        grouped_matches_list = [
            (log_record, matches_list) 
            for log_record, matches_list in sorted(
                grouped_matches.items(), 
                key=lambda x: x[0].record_index
            )
        ]
        
        # Pagination
        paginator = Paginator(grouped_matches_list, self.paginate_by)
        page_number = self.request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        # Get filter options from all matches (not just current page)
        all_matches = RuleMatch.objects.filter(artefact=artefact).prefetch_related(
            'rule__tags', 'rule__mitre_techniques'
        )

        # Ai Analysis Results
        ai_artefact_analysis_result = AIAnalysisResult.objects.filter(artefact=artefact).first()
        
        available_tags = set()
        available_techniques = set()
        
        for match in all_matches:
            available_tags.update(match.rule.tags.values_list('name', flat=True))
            for technique in match.rule.mitre_techniques.all():
                available_techniques.add((
                    technique.technique_id,
                    technique.name,
                    technique.description
                ))
        
        context.update({
            "artefact": artefact,
            "ai_artefact_analysis_result": ai_artefact_analysis_result,
            "page_obj": page_obj,
            "grouped_matches": page_obj.object_list,
            "total_matches": matches_qs.count(),
            "unique_rules_count": len(unique_rules),
            "status_counts": status_counts,
            "available_tags": sorted(available_tags),
            "available_techniques": available_techniques,
            
            # Current filter values for form persistence
            "current_search": search_query,
            "current_status": status_filter,
            "current_tag": tag_filter,
            "current_mitre": mitre_filter,
            "expand_all": expand_all,
        })
        
        return context


# Optional: Add a simple AJAX view for quick filtering without page reload
from django.http import JsonResponse
from django.template.loader import render_to_string
from datetime import timedelta
import pprint

@login_required
def filter_matches_ajax(request, pk):
    """AJAX endpoint for live filtering without page reload"""
    if not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'error': 'Invalid request'}, status=400)
    
    artefact = get_object_or_404(Artefact, id=pk, assigned_to=request.user)
    
    # Get filter params
    search_query = request.GET.get('search', '').strip()
    status_filter = request.GET.get('status', '')
    tag_filter = request.GET.get('tag', '')
    
    # Apply same filtering logic as main view
    matches_qs = RuleMatch.objects.filter(artefact=artefact)
    
    if search_query:
        matches_qs = matches_qs.filter(
            Q(rule__name__icontains=search_query) |
            Q(rule__description__icontains=search_query) |
            Q(log_record__content__icontains=search_query)
        )
    
    if tag_filter:
        matches_qs = matches_qs.filter(rule__tags__name=tag_filter)
    
    if status_filter == 'passed':
        matches_qs = matches_qs.annotate(
            failed_evals=Count('logic_evaluations', filter=Q(logic_evaluations__passed=False))
        ).filter(failed_evals=0)
    elif status_filter == 'failed':
        matches_qs = matches_qs.filter(logic_evaluations__passed=False).distinct()
    
    matches_qs = matches_qs.select_related('rule', 'log_record').prefetch_related(
        'logic_evaluations__logic_unit', 'rule__tags', 'rule__mitre_techniques'
    ).order_by('log_record__record_index', 'matched_at')
    
    # Group and render
    grouped_matches = defaultdict(list)
    for match in matches_qs:
        grouped_matches[match.log_record].append(match)
    
    grouped_matches_list = [
        (log_record, matches_list) 
        for log_record, matches_list in sorted(
            grouped_matches.items(), 
            key=lambda x: x[0].record_index
        )
    ]
    
    # Render partial template
    html = render_to_string('analysis/partials/matches_accordion.html', {
        'grouped_matches': grouped_matches_list,
        'expand_all': request.GET.get('expand_all', False)
    })
    
    return JsonResponse({
        'html': html,
        'count': matches_qs.count()
    })

@method_decorator(login_required, name='dispatch')
class IncidentAnalysisDashboardView(TemplateView):
    template_name = "analysis/incident_result.html"

    def get_context_data(self, **kwargs):
        incidents = Incident.objects.filter(responders=self.request.user).prefetch_related('artefacts__rule_matches')
        return {
            "incidents": incidents
        }

def ai_intel_generated_rules_view(request):

    context = generate_rules_from_internet_intel()

    return render(request, "analysis/ai/ai_intel_rules.html", context)