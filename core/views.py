from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.shortcuts import get_object_or_404, render
from django.http import JsonResponse
from django.views.generic import ListView, DetailView, CreateView, UpdateView, View
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.urls import reverse_lazy
from .models import *
from .forms import *
from django.views.generic.edit import DeleteView
from .parser import parse_artefact_file
from django.db.models import Q
from .utils import infer_artefact_type


# === Dashboard View ===

class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "core/dashboard.html"


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
        return JsonResponse({
            "status": "success",
            "note_id": note.id,
            "message": "Note added successfully"
        })