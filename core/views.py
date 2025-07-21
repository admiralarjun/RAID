
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.shortcuts import get_object_or_404, render
from django.http import JsonResponse, HttpResponse
from django.utils.timezone import localtime
import csv, json
from textwrap import shorten
from fpdf import FPDF
from datetime import datetime
from django.template.loader import render_to_string
from django.views.generic import ListView, DetailView, CreateView, UpdateView, View
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.urls import reverse_lazy
from .models import *
from analysis.models import IncidentAction
from .forms import *
from django.views.generic.edit import DeleteView
from .parser import parse_artefact_file
from django.db.models import Q
from .utils import infer_artefact_type
from django.shortcuts import redirect


from django.db.models import Count, Q
from django.utils import timezone
from datetime import datetime, timedelta
from .models import Incident, Artefact, Client, UserProfile
from analysis.models import RuleMatch, AIAnalysisResult, IncidentAnalysisResult


# === Dashboard View ===
class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "core/dashboard.html"
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        
        # Get user profile for role-based content
    
        
        # === KEY METRICS ===
        context['total_incidents'] = Incident.objects.count()
        context['active_incidents'] = Incident.objects.exclude(status='closed').count()
        context['critical_incidents'] = Incident.objects.filter(severity='critical').exclude(status='closed').count()
        context['total_clients'] = Client.objects.filter(is_active=True).count()
        context['total_artefacts'] = Artefact.objects.count()
        context['pending_analysis'] = Artefact.objects.filter(ai_results__isnull=True).count()
        
        # === RECENT ACTIVITY ===
        # Recent incidents (last 7 days)
        seven_days_ago = timezone.now() - timedelta(days=7)
        context['recent_incidents'] = Incident.objects.filter(
            created_at__gte=seven_days_ago
        ).select_related('client', 'incident_manager').order_by('-created_at')[:5]
        
        # Recent artefacts uploaded
        context['recent_artefacts'] = Artefact.objects.filter(
            uploaded_at__gte=seven_days_ago
        ).select_related('incident', 'uploaded_by').order_by('-uploaded_at')[:5]
        
        # Recent rule matches (security detections)
        context['recent_detections'] = RuleMatch.objects.filter(
            matched_at__gte=seven_days_ago
        ).select_related('rule', 'artefact', 'log_record').order_by('-matched_at')[:5]
        
        # === STATUS BREAKDOWN ===
        status_counts = Incident.objects.values('status').annotate(count=Count('id'))
        context['status_breakdown'] = {item['status']: item['count'] for item in status_counts}
        
        # === SEVERITY BREAKDOWN ===
        severity_counts = Incident.objects.values('severity').annotate(count=Count('id'))
        context['severity_breakdown'] = {item['severity']: item['count'] for item in severity_counts}
   
        # === ANALYSIS STATS ===
        context['total_ai_analyses'] = AIAnalysisResult.objects.count()
        context['incident_analyses'] = IncidentAnalysisResult.objects.count()
        
        # Recent AI analyses
        context['recent_ai_analyses'] = AIAnalysisResult.objects.select_related(
            'artefact', 'artefact__incident'
        ).order_by('-generated_at')[:5]
        
        # === PRIORITY INCIDENTS ===
        context['priority_incidents'] = Incident.objects.filter(
            Q(severity='critical') | Q(severity='high')
        ).exclude(status='closed').select_related('client', 'incident_manager').order_by('-created_at')[:5]
        
        # === WORKLOAD DISTRIBUTION ===
        context['analyst_workload'] = UserProfile.objects.filter(
            role__in=['incident_responder', 'lead_responder']
        ).annotate(
            active_incidents=Count('user__assigned_incidents', filter=Q(user__assigned_incidents__status__in=['accepted', 'in_progress']))
        ).order_by('-active_incidents')[:5]
        
        return context

# === Incident Views ===

class IncidentListView(LoginRequiredMixin, ListView):
    model = Incident
    template_name = "core/incidents/incident_list.html"
    context_object_name = "incidents"
    ordering = ["-created_at"]

class IncidentCreateView(LoginRequiredMixin, CreateView):
    model = Incident
    form_class = IncidentForm
    template_name = "core/incidents/create_form.html"
    success_url = reverse_lazy("core:incident_list")

class IncidentUpdateView(LoginRequiredMixin, UpdateView):
    model = Incident
    form_class = IncidentUpdateForm
    template_name = "core/incidents/incident_update.html"
    slug_field = 'incident_id'
    slug_url_kwarg = 'incident_id'
    success_url = reverse_lazy("core:incident_list")

class IncidentDetailView(LoginRequiredMixin, DetailView):
    model = Incident
    template_name = "core/incidents/incident_detail.html"
    slug_field = 'incident_id'
    slug_url_kwarg = 'incident_id'
    context_object_name = "incident"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        incident = ctx['incident']

        # Per-artefact latest AI result lookup
        ctx['artefact_ai'] = {
            arte.id: arte.ai_results.order_by('-generated_at').first()
            for arte in incident.artefacts.all()
        }

        # Incident-level analysis
        incident_ai = incident.ai_incident_results.order_by('-generated_at').first()
        ctx['incident_ai'] = incident_ai

        if incident_ai and incident_ai.graphs:
                try:
                    graphs = json.loads(incident_ai.graphs)
                except Exception as e:
                    graphs = {}
        else:
            graphs = {}

        ctx['action_hypothesis_chord'] = graphs.get('action_hypothesis_chord', {})
        ctx['adversary_path_sankey'] = graphs.get('adversary_path_sankey', [])
        ctx['mitre_heatmap'] = graphs.get('mitre_heatmap', [])

        if incident_ai:
            ctx['hypotheses'] = list(incident_ai.hypotheses.all())
            ctx['actions'] = list(
                IncidentAction.objects.filter(hypothesis__analysis=incident_ai)
            )
        else:
            ctx['hypotheses'] = []
            ctx['actions'] = []

        return ctx

class IncidentDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = Incident
    template_name = "core/incidents/incident_confirm_delete.html"
    pk_url_kwarg = 'pk'
    context_object_name = "incident"
    success_url = reverse_lazy("core:incident_list")

    def test_func(self):
        return self.request.user.is_superuser or self.request.user == self.get_object().incident_manager
    
# === Client Views ===

class ClientListView(LoginRequiredMixin, ListView):
    model = Client
    template_name = "core/clients/client_list.html"
    context_object_name = "clients"

class ClientCreateView(LoginRequiredMixin, CreateView):
    model = Client
    form_class = ClientForm
    template_name = "core/clients/client_form.html"
    success_url = reverse_lazy("core:client_list")

class ClientDetailView(LoginRequiredMixin, DetailView):
    model = Client
    template_name = "core/clients/client_detail.html"
    context_object_name = "client"

class ClientUpdateView(LoginRequiredMixin, UpdateView):
    model = Client
    form_class = ClientUpdateForm
    template_name = "core/clients/client_update.html"
    pk_url_kwarg = 'pk'
    success_url = reverse_lazy("core:client_list")

class ClientDeleteView(LoginRequiredMixin, DeleteView):
    model = Client
    template_name = "core/clients/client_confirm_delete.html"
    pk_url_kwarg = 'pk'
    context_object_name = "client"
    success_url = reverse_lazy("core:client_list")

# === User Profile Views ===

class UserProfileListView(LoginRequiredMixin, ListView):
    model = UserProfile
    template_name = "core/users/list.html"
    context_object_name = "profiles"

class UserProfileUpdateView(LoginRequiredMixin, UpdateView):
    model = UserProfile
    form_class = UserProfileForm
    template_name = "core/users/user_profileform.html"
    success_url = reverse_lazy("core:profile_list")


# === Artefacts Views ===

class ArtefactUploadView(LoginRequiredMixin, View):
    template_name = "core/artefacts/artefact_form.html"

    def get(self, request):
        incident_id = request.GET.get("incident")
        form = ArtefactForm(initial={'incident': incident_id} if incident_id else None)
        users = User.objects.all()
        incident = Incident.objects.filter(pk=incident_id).first() if incident_id else None
        return render(request, self.template_name, {
            'form': form,
            'users': users,
            'incident': incident
        })

    def post(self, request):
        form = ArtefactForm(request.POST)
        files = request.FILES.getlist('file')
        users = User.objects.all()

        incident = None
        uploaded_files = []

        if form.is_valid() and files:
            incident = form.cleaned_data['incident']

            for idx, f in enumerate(files):
                assigned_to_id = request.POST.get(f'assigned_to_{idx}')
                assigned_to = User.objects.filter(id=assigned_to_id).first() if assigned_to_id else None

                artefact = Artefact.objects.create(
                    incident=incident,
                    name=f.name,
                    file=f,
                    uploaded_by=request.user,
                    assigned_to=assigned_to,
                    artefact_type=infer_artefact_type(f.name)
                )
                parse_artefact_file(artefact)
                uploaded_files.append(artefact)

            return render(request, self.template_name, {
                'form': ArtefactForm(initial={'incident': incident.pk}),
                'users': users,
                'incident': incident,
                'success': True
            })

        return render(request, self.template_name, {
            'form': form,
            'users': users,
            'incident': incident,
            'error': True
        })

class ArtefactUpdateView(LoginRequiredMixin, UpdateView):
    model = Artefact
    form_class = ArtefactUpdateForm
    template_name = "core/artefacts/artefact_form.html"
    context_object_name = "artefact"

    def get_success_url(self):
        return reverse_lazy("core:artefact_detail", kwargs={"pk": self.object.pk})


class ArtefactDeleteView(LoginRequiredMixin, DeleteView):
    model = Artefact
    template_name = "core/artefacts/artefact_confirm_delete.html"
    context_object_name = "artefact"
    success_url = reverse_lazy("core:artefact_list")

    def get_success_url(self):
        next_url = self.request.GET.get("next") or self.request.POST.get("next")
        if next_url:
            return next_url
        return super().get_success_url()

class ArtefactDetailView(LoginRequiredMixin, DetailView):
    model = Artefact
    template_name = "core/artefacts/artefact_detail.html"
    context_object_name = "artefact"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        artefact = self.get_object()

        # Handle filter
        filters = self.request.GET.getlist('filter')
        query = Q()
        for f in filters:
            if ':' in f:
                op, val = f.split(':', 1)
                if op == 'contains':
                    query &= Q(content__icontains=val.strip())
                elif op == 'notcontains':
                    query &= ~Q(content__icontains=val.strip())
                # Extend here for other ops like 'startswith', etc.

        records = artefact.records.filter(query) if filters else artefact.records.all()

        context["records"] = records
        context["notes"] = artefact.notes.select_related("author", "record")
        context["note_form"] = ArtefactNoteForm()
        context["applied_filters"] = filters
        return context


class ArtefactListView(LoginRequiredMixin, ListView):
    model = Artefact
    template_name = "core/artefacts/artefact_list.html"
    context_object_name = "artefacts"
    ordering = ['-uploaded_at']


class LogRecordPermalinkView(LoginRequiredMixin, DetailView):
    model = LogRecord
    template_name = "core/artefacts/log_record_permalink.html"
    context_object_name = "record"


class AddArtefactNoteView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        artefact_id = request.POST.get("artefact_id")
        record_id = request.POST.get("record_id")
        content = request.POST.get("content")

        artefact = get_object_or_404(Artefact, pk=artefact_id)
        record = get_object_or_404(LogRecord, pk=record_id) if record_id else None

        note = ArtefactNote.objects.create(
            artefact=artefact,
            record=record,
            author=request.user,
            content=content,
        )
        return redirect("core:artefact_detail", pk=artefact_id)

class IncidentCSVExportView(LoginRequiredMixin, View):
    def get(self, request, incident_id):
        incident = Incident.objects.get(incident_id=incident_id)
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="incident_{incident_id}.csv"'

        writer = csv.writer(response)
        writer.writerow(['Incident ID', 'Title', 'Status', 'Severity'])
        writer.writerow([incident.incident_id, incident.title, incident.get_status_display(), incident.get_severity_display()])

        writer.writerow([])
        writer.writerow(['Artefacts'])
        writer.writerow(['Name', 'Type', 'Uploader', 'Uploaded', 'AI Status'])

        for artefact in incident.artefacts.all():
            ai_result = artefact.ai_results.order_by('-generated_at').first()
            writer.writerow([
                artefact.name,
                artefact.get_artefact_type_display(),
                str(artefact.uploaded_by),
                artefact.uploaded_at,
                'Analyzed' if ai_result else 'Pending'
            ])

        return response
    

    
# Full Incident Report PDF Generator - Extended


class KPMGIncidentReportPDF(FPDF):
    def __init__(self, title="Incident Response Report"):
        super().__init__()
        self.title = title
        self.set_auto_page_break(auto=True, margin=15)

    def clean_text(self, text):
        """Clean and replace Unicode characters not supported by Latin-1."""
        if not text:
            return ""
        replacements = {
            '\u2013': '-', '\u2014': '-',  # Dashes
            '\u2018': "'", '\u2019': "'",  # Single quotes
            '\u201c': '"', '\u201d': '"',  # Double quotes
            '\xa0': ' ',                   # Non-breaking space
        }
        for bad, good in replacements.items():
            text = text.replace(bad, good)
        return str(text).encode('latin-1', errors='replace').decode('latin-1')

    def header(self):
        self.set_fill_color(0, 51, 102)
        self.rect(0, 0, 210, 20, 'F')

        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'BI', 14)
        self.cell(0, 10, self.clean_text("KPMG Cybersecurity"), ln=True, align='L')

        self.set_font('Helvetica', 'B', 12)
        self.cell(0, 5, self.clean_text(self.title), ln=True, align='L')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        self.cell(0, 10, self.clean_text(f'Page {self.page_no()} | Generated on {timestamp}'), 0, 0, 'C')
    
    
    def add_horizontal_rule(self, thickness=0.5, y_offset=2):
        """Draws a horizontal line across the page."""
        x1 = 10
        x2 = 200
        y = self.get_y() + y_offset
        self.set_line_width(thickness)
        self.line(x1, y, x2, y)

    def add_section_header(self, title):
        """Primary section header with background and horizontal rule."""
        self.set_fill_color(0, 51, 102)
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 12)
        self.cell(0, 8, self.clean_text(f"  {title}"), ln=True, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(4)

    def add_subsection_header(self, subtitle):
        """Secondary subsection header with horizontal rule."""
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(0, 51, 102)
        self.add_horizontal_rule(thickness=0.3, y_offset=0.5)  # Slightly thinner line for subsection
        self.cell(0, 6, self.clean_text(subtitle), ln=True)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def add_key_value_pair(self, key, value):
        self.set_font('Helvetica', 'B', 10)
        self.cell(50, 7, self.clean_text(f"{key}:"), ln=False)

        self.set_font('Helvetica', '', 10)
        self.multi_cell(0, 7, self.clean_text(str(value) if value else "N/A"))

    def add_information_section(self, title, content):
        # Section Title
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(0, 51, 102)
        self.multi_cell(0, 7, self.clean_text(title))
        self.ln(1)

        # Content
        self.set_font('Helvetica', '', 10)
        self.set_text_color(0, 0, 0)
        self.multi_cell(0, 6, self.clean_text(content))
        self.ln(4)

    def add_table_header(self, headers, col_widths):
        self.set_fill_color(200, 200, 200)
        self.set_font('Helvetica', 'B', 9)
        for i, header in enumerate(headers):
            self.cell(col_widths[i], 7, self.clean_text(header), 1, 0, 'C', True)
        self.ln()

    def add_table_row(self, values, col_widths, alternate_row=False):
        self.set_fill_color(245, 245, 245) if alternate_row else self.set_fill_color(255, 255, 255)
        self.set_font('Helvetica', '', 9)
        for i, value in enumerate(values):
            self.cell(col_widths[i], 6, self.clean_text(str(value))[:30], 1, 0, 'L', True)
        self.ln()

    def add_bullet_point(self, text, indent=0):
        self.set_font('Helvetica', '', 10)
        self.cell(indent * 10, 6, '', ln=False)
        self.cell(5, 6, '-', ln=False)
        self.multi_cell(0, 6, self.clean_text(str(text)))

class FullIncidentReportPDF(KPMGIncidentReportPDF):
    def add_incident_details(self, incident):
        self.add_section_header("Incident Details")
        self.add_key_value_pair("Incident ID", incident.incident_id)
        self.add_key_value_pair("Title", incident.title)
        self.add_key_value_pair("Description", incident.description)
        self.add_key_value_pair("Status", incident.get_status_display())
        self.add_key_value_pair("Severity", incident.get_severity_display())
        self.add_key_value_pair("Client", incident.client.name)
        self.add_key_value_pair("Organization", incident.client.organization)
        self.add_key_value_pair("Incident Manager", incident.incident_manager)
        self.add_key_value_pair("Lead Responder", incident.lead_responder or "Not Assigned")
        self.add_key_value_pair("Response Team", ", ".join(str(r) for r in incident.responders.all()) or "Not Assigned")
        self.add_key_value_pair("Reported Date", localtime(incident.created_at).strftime('%d %B %Y at %H:%M'))
        if incident.accepted_at:
            self.add_key_value_pair("Accepted At", localtime(incident.accepted_at).strftime('%d %B %Y at %H:%M'))
        if incident.closed_at:
            self.add_key_value_pair("Closed At", localtime(incident.closed_at).strftime('%d %B %Y at %H:%M'))
        self.add_key_value_pair("Client Can View Analysis", incident.client_can_view_analysis)
        self.add_key_value_pair("Client Can View Reports", incident.client_can_view_reports)

    def add_executive_summary_box(self, incident):
        summary_text = (
            f"Incident '{incident.title}' (ID: {incident.incident_id}) was reported by {incident.client.name}. "
            f"It is categorized as {incident.get_severity_display()} severity and is currently {incident.get_status_display()}.\n\n"
            f"Lead Responder: {incident.lead_responder or 'Not Assigned'}\n"
            f"Total Artefacts: {incident.artefacts.count()}\n"
            f"Response Team: {', '.join(str(r) for r in incident.responders.all()) or 'Not Assigned'}"
        )
        self.add_information_section("Executive Summary", summary_text)

    def add_client_contact_details(self, client):
        self.add_section_header("Client Contact Details")
        self.add_key_value_pair("Client Name", client.name)
        self.add_key_value_pair("Organization", client.organization)
        self.add_key_value_pair("Contact Person", client.contact_person)
        self.add_key_value_pair("Email", client.email)
        self.add_key_value_pair("Phone", client.phone)
        self.add_key_value_pair("Address", client.address)

    def add_artefact_notes(self, artefact):
        notes = artefact.notes.all()
        if notes:
            self.add_subsection_header(f"Notes for Artefact: {artefact.name}")
            for note in notes:
                author = note.author or "Unknown"
                self.add_bullet_point(f"{author}: {note.content}")

    def add_rule_matches(self, artefact):
        rule_matches = artefact.rule_matches.select_related('rule').all()
        if rule_matches:
            self.add_subsection_header(f"Detection Summary for Artefact: {artefact.name}")
            for match in rule_matches:
                self.add_bullet_point(f"Rule: {match.rule.name} on Record {match.log_record.record_index} at {match.matched_at:%Y-%m-%d %H:%M}")

    def add_ai_analysis_details(self, ai_result):
        self.add_section_header("AI Detailed Analysis")
        self.add_key_value_pair("Narrative", ai_result.narrative)
        if ai_result.highlights:
            highlights = "\n".join([f"Line {h['record_index']}: {h['excerpt']} - {h['reason']}" for h in ai_result.highlights])
            self.add_horizontal_rule(thickness=0.3, y_offset=1)
            self.add_information_section("Key Highlights", highlights)
        if ai_result.references:
            references = "\n".join([f"Rule {r['rule_name']} on Record {r['record_index']} ({', '.join(r.get('mitre_techniques', []))})" for r in ai_result.references])
            self.add_horizontal_rule(thickness=0.3, y_offset=1)
            self.add_information_section("References", references)

class IncidentPDFExportView(LoginRequiredMixin, View):
    def get(self, request, incident_id):
        incident = Incident.objects.prefetch_related(
            'artefacts__notes',
            'artefacts__rule_matches__rule',
            'artefacts__ai_results',
            'ai_incident_results__hypotheses__actions',
        ).select_related('client', 'incident_manager', 'lead_responder').get(incident_id=incident_id)

        incident_ai = incident.ai_incident_results.order_by('-generated_at').first()

        pdf = FullIncidentReportPDF(title=incident.title)
        pdf.add_page()

        # Executive Summary
        pdf.add_executive_summary_box(incident)

        # Incident Details
        pdf.add_incident_details(incident)

        # Client Contact
        pdf.add_client_contact_details(incident.client)

        # Artefacts Section
        pdf.add_section_header("Evidence & Artefacts")
        for artefact in incident.artefacts.all():
            pdf.add_key_value_pair("Artefact", artefact.name)
            pdf.add_key_value_pair("Type", artefact.get_artefact_type_display())
            pdf.add_key_value_pair("Uploaded By", artefact.uploaded_by or "Unknown")
            pdf.add_key_value_pair("Assigned To", artefact.assigned_to or "Not Assigned")
            pdf.add_key_value_pair("Parsed", artefact.parsed)
            pdf.add_key_value_pair("Uploaded At", localtime(artefact.uploaded_at).strftime('%d/%m/%Y'))

            ai_result = artefact.ai_results.order_by('-generated_at').first()
            if ai_result:
                pdf.add_ai_analysis_details(ai_result)

            pdf.add_artefact_notes(artefact)
            pdf.add_rule_matches(artefact)
            pdf.ln(5)

        # Threat Hypotheses Section
        if incident_ai:
            pdf.add_section_header("Threat Hypotheses")
            for i, h in enumerate(incident_ai.hypotheses.all(), 1):
                pdf.set_font('Helvetica', 'B', 11)
                pdf.multi_cell(0, 7, pdf.clean_text(f"Hypothesis {i}: {h.description}"))

                # Artefacts and MITRE Techniques (use cell, not multi_cell)
                if h.artefacts:
                    pdf.add_key_value_pair("Related Artefacts", ", ".join(h.artefacts))
                if h.mitre_techniques:
                    pdf.add_key_value_pair("MITRE Techniques", ", ".join(h.mitre_techniques))

                # Actions (use single cell or clean text inside multi_cell)
                actions = h.actions.all()
                if actions.exists():
                    pdf.add_subsection_header("Response Actions")
                    for act in actions:
                        action_text = f"{act.description} [{act.get_status_display()}]"
                        pdf.set_font('Helvetica', '', 10)
                        pdf.multi_cell(0, 6, pdf.clean_text(action_text))  # OR use cell() if single-line

        # Confidentiality Footer
        pdf.ln(10)
        pdf.set_font('Helvetica', 'I', 8)
        pdf.set_text_color(128, 128, 128)
        pdf.multi_cell(0, 5, "This report contains confidential and privileged information.")

        # HTTP Response
        response = HttpResponse(pdf.output(dest='S').encode('latin1'), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="Incident_Report_{incident_id}.pdf"'
        return response
    
