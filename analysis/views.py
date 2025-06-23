# analysis/views.py
from django.views.generic import ListView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from django.shortcuts import redirect
from django.http import HttpResponse
from django.shortcuts import render

from .models import Rule, LogicUnit, RuleTag
from .forms import RuleForm, LogicUnitForm, RuleTagForm


# === Rule Views ===

class RuleListView(ListView):
    model = Rule
    context_object_name = "rules"
    template_name = "analysis/rule/list.html"


class RuleCreateView(CreateView):
    model = Rule
    form_class = RuleForm
    template_name = "analysis/rule/form.html"

    def form_valid(self, form):
        self.object = form.save()
        return render(self.request, "analysis/rule/partials/item.html", {"rule": self.object})


class RuleUpdateView(UpdateView):
    model = Rule
    form_class = RuleForm
    template_name = "analysis/rule/form.html"

    def form_valid(self, form):
        self.object = form.save()
        return render(self.request, "analysis/rule/partials/item.html", {"rule": self.object})


class RuleDeleteView(DeleteView):
    model = Rule
    template_name = "analysis/rule/confirm_delete.html"
    success_url = reverse_lazy("analysis:rule_list")

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        self.object.delete()
        return HttpResponse(status=204)


# === LogicUnit Views ===

class LogicUnitListView(ListView):
    model = LogicUnit
    context_object_name = "logics"
    template_name = "analysis/logicunit/list.html"


class LogicUnitCreateView(CreateView):
    model = LogicUnit
    form_class = LogicUnitForm
    template_name = "analysis/logicunit/form.html"

    def form_valid(self, form):
        self.object = form.save()
        return render(self.request, "analysis/logicunit/partials/item.html", {"logic": self.object})


class LogicUnitUpdateView(UpdateView):
    model = LogicUnit
    form_class = LogicUnitForm
    template_name = "analysis/logicunit/form.html"

    def form_valid(self, form):
        self.object = form.save()
        return render(self.request, "analysis/logicunit/partials/item.html", {"logic": self.object})


class LogicUnitDeleteView(DeleteView):
    model = LogicUnit
    template_name = "analysis/logicunit/confirm_delete.html"
    success_url = reverse_lazy("analysis:logicunit_list")

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        self.object.delete()
        return HttpResponse(status=204)


# === Optional: Tag CRUD ===

class RuleTagCreateView(CreateView):
    model = RuleTag
    form_class = RuleTagForm
    template_name = "analysis/rule/tag_form.html"

    def form_valid(self, form):
        self.object = form.save()
        return HttpResponse(f"<option value='{self.object.pk}' selected>{self.object.name}</option>")
