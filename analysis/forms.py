# analysis/forms.py
from django import forms
from .models import LogicUnit, Rule, RuleTag
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit

class LogicUnitForm(forms.ModelForm):
    class Meta:
        model = LogicUnit
        fields = ["label", "evaluate", "pattern", "negate"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_tag = False  # HTMX form already wrapped
        self.helper.label_class = "form-label"
        self.helper.field_class = "form-control"


class RuleTagForm(forms.ModelForm):
    class Meta:
        model = RuleTag
        fields = ["name"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.label_class = "form-label"
        self.helper.field_class = "form-control"


class RuleForm(forms.ModelForm):
    logic_units = forms.ModelMultipleChoiceField(
        queryset=LogicUnit.objects.all(),
        required=False,
        widget=forms.SelectMultiple(attrs={"class": "form-select"})
    )

    class Meta:
        model = Rule
        fields = ["name", "description", "reference", "tags", "is_enabled", "logic_units", "condition_json"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["tags"].widget.attrs.update({"class": "form-select", "multiple": "multiple"})
        self.fields["is_enabled"].widget.attrs.update({"class": "form-check-input"})

        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.label_class = "form-label"
        self.helper.field_class = "form-control"
