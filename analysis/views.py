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
from collections import defaultdict
from django.db.models import Q, Prefetch
from django.core.paginator import Paginator


@method_decorator(login_required, name='dispatch')
class UnifiedDashboardView(TemplateView):
    template_name = "analysis/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        
        # Enhanced artefacts with statistics
        artefacts = Artefact.objects.filter(
            assigned_to=user
        ).select_related('incident').annotate(
            record_count=Count('records'),
            match_count=Count('rule_matches'),
            recent_matches=Count(
                'rule_matches',
                filter=Q(rule_matches__matched_at__gte=timezone.now() - timedelta(days=7))
            )
        ).order_by('-uploaded_at')

        # Enhanced incidents with statistics
        incidents = Incident.objects.filter(
            responders=user
        ).prefetch_related('responders').annotate(
            artefact_count=Count('artefacts'),
            total_matches=Count('artefacts__rule_matches')
        ).order_by('-created_at')

        # Recent matches with better context
        recent_matches = RuleMatch.objects.filter(
            artefact__assigned_to=user
        ).select_related(
            'rule', 'log_record', 'artefact__incident'
        ).order_by('-matched_at')[:12]

        # Dashboard statistics
        stats = {
            'total_artefacts': artefacts.count(),
            'active_incidents': incidents.count(),
            'total_matches': RuleMatch.objects.filter(artefact__assigned_to=user).count(),
            'matches_today': RuleMatch.objects.filter(
                artefact__assigned_to=user,
                matched_at__date=timezone.now().date()
            ).count(),
            'high_activity_artefacts': artefacts.filter(recent_matches__gt=5).count(),
        }

        # Resume analysis - enhanced
        resume_artefact = None
        last_artefact_id = self.request.session.get("last_analysed_artefact_id")
        if last_artefact_id:
            resume_artefact = artefacts.filter(id=last_artefact_id).first()

        # Most active rules
        top_rules = Rule.objects.filter(
            matches__artefact__assigned_to=user,
            is_enabled=True
        ).annotate(
            match_count=Count('matches')
        ).prefetch_related('tags').order_by('-match_count')[:5]

        # Priority artefacts (high activity or recent matches)
        priority_artefacts = artefacts.filter(
            Q(recent_matches__gt=3) | Q(match_count__gt=10)
        ).distinct()[:5]

        context.update({
            'artefacts': artefacts,
            'incidents': incidents,
            'recent_matches': recent_matches,
            'resume_artefact': resume_artefact,
            'stats': stats,
            'top_rules': top_rules,
            'priority_artefacts': priority_artefacts,
        })
        
        return context
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
