from django import forms
from django.contrib.auth.models import User
from .models import *
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit


class IncidentForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = [
            'title', 'description', 'client',
            'incident_manager', 'lead_responder', 'responders',
            'status', 'severity', 'client_can_view_analysis', 'client_can_view_reports'
        ]
        widgets = {
            'responders': forms.CheckboxSelectMultiple,
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = "post"
        self.helper.add_input(Submit("submit", "Save Incident"))

class IncidentUpdateForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = [
            'title', 'description', 'client',
            'incident_manager', 'lead_responder', 'responders',
            'status', 'severity', 'client_can_view_analysis', 'client_can_view_reports'
        ]
        widgets = {
            'responders': forms.CheckboxSelectMultiple,
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = "post"
        self.helper.add_input(Submit("submit", "Update Incident"))


class ClientForm(forms.ModelForm):
    class Meta:
        model = Client
        fields = ['name', 'organization', 'contact_person', 'email', 'phone', 'address', 'authorized_users']
        widgets = {
            'authorized_users': forms.CheckboxSelectMultiple,
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = "post"
        self.helper.add_input(Submit("submit", "Save Client"))

class ClientUpdateForm(forms.ModelForm):
    class Meta:
        model = Client
        fields = ['name', 'organization', 'contact_person', 'email', 'phone', 'address', 'authorized_users']
        widgets = {
            'authorized_users': forms.CheckboxSelectMultiple,
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = "post"
        self.helper.add_input(Submit("submit", "Update Client"))

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['user', 'role', 'avatar', 'organization', 'phone', 'is_active']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = "post"
        self.helper.add_input(Submit("submit", "Save Profile"))



class ArtefactForm(forms.Form):
    incident = forms.ModelChoiceField(queryset=Incident.objects.all(), label="Incident")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.attrs = {'enctype': 'multipart/form-data'}
        self.helper.add_input(Submit('submit', 'Upload Artefacts'))

class ArtefactUpdateForm(forms.ModelForm):
    class Meta:
        model = Artefact
        fields = ['name', 'assigned_to']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.add_input(Submit('submit', 'Update Artefact'))

class ArtefactNoteForm(forms.ModelForm):
    class Meta:
        model = ArtefactNote
        fields = ['record', 'content']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['record'].required = False
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.add_input(Submit('submit', 'Save Note'))


class LogRecordForm(forms.ModelForm):
    class Meta:
        model = LogRecord
        fields = ['artefact', 'record_index', 'content']
        widgets = {
            'metadata': forms.Textarea(attrs={'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.add_input(Submit('submit', 'Save Log Record'))