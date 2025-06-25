# core/models.py
from django.db import models
from django.contrib.auth.models import User
import uuid, re

class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('incident_manager', 'Incident Manager'),
        ('incident_responder', 'Incident Responder'),
        ('client', 'Client'),
        ('lead_responder', 'Lead Responder'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    organization = models.CharField(max_length=255, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    avatar = models.ImageField(upload_to="avatars/", blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username} - {self.get_role_display()}"

    def get_avatar_url(self):
        if self.avatar:
            return self.avatar.url
        return "/static/images/default-avatar.png"  # fallback image


class Client(models.Model):
    name = models.CharField(max_length=255)
    organization = models.CharField(max_length=255)
    contact_person = models.ForeignKey(User, on_delete=models.CASCADE, related_name='managed_clients')
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    address = models.TextField(blank=True)
    onboarded_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    authorized_users = models.ManyToManyField(User, related_name='accessible_clients', blank=True)

    def __str__(self):
        return f"{self.name} ({self.organization})"


class Incident(models.Model):
    STATUS_CHOICES = [
        ('ticket_raised', 'Ticket Raised'),
        ('accepted', 'Accepted'),
        ('in_progress', 'In Progress'),
        ('analysis_complete', 'Analysis Complete'),
        ('report_draft', 'Report Draft'),
        ('report_final', 'Report Final'),
        ('closed', 'Closed'),
    ]
    
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]

    incident_id = models.CharField(max_length=50, unique=True, blank=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='incidents')
    incident_manager = models.ForeignKey(User, on_delete=models.CASCADE, related_name='managed_incidents')
    lead_responder = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='led_incidents')
    responders = models.ManyToManyField(User, related_name='assigned_incidents', blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ticket_raised')
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    client_can_view_analysis = models.BooleanField(default=False)
    client_can_view_reports = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.incident_id}: {self.title}"

    def get_absolute_url(self):
        return f"/incidents/{self.incident_id}/"
    
    def save(self, *args, **kwargs):
        if not self.incident_id and self.client:
            # 1. Uppercase + replace spaces with underscores
            name = self.client.name.upper().replace(" ", "_")
            # 2. Remove non-alphanumeric and underscore characters
            clean_name = re.sub(r'[^A-Z0-9_]', '', name)
            # 3. Truncate to max 5 characters (do not pad)
            prefix = clean_name[:5]

            # 4. Count existing incidents for this client
            count = Incident.objects.filter(client=self.client).count() + 1
            suffix = f"{count:04d}"

            self.incident_id = f"{prefix}_{suffix}"

        super().save(*args, **kwargs)


class Artefact(models.Model):
    ARTEFACT_TYPES = [
        ('evtx', 'Windows Event Log (EVTX)'),
        ('pcap', 'Packet Capture (PCAP)'),
        ('log', 'Logs Files'),
        ('firewall', 'Firewall Logs'),
        ('other', 'Other'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    incident = models.ForeignKey("Incident", on_delete=models.CASCADE, related_name="artefacts")
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name="uploaded_artefacts")
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="working_artefacts")
    name = models.CharField(max_length=255)
    artefact_type = models.CharField(max_length=20, choices=ARTEFACT_TYPES, default='other')
    file = models.FileField(upload_to='artefacts/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    parsed = models.BooleanField(default=False)

    def get_artefact_id(self):
        return str(self.id)

    def __str__(self):
        return f"{self.name} ({self.artefact_type})"
    

class LogRecord(models.Model):
    artefact = models.ForeignKey(Artefact, on_delete=models.CASCADE, related_name="records")
    record_index = models.PositiveIntegerField()  # Line or entry number
    content = models.TextField()  # Raw or parsed line

    def __str__(self):
        return f"{self.artefact.name} - Record #{self.record_index}"


class ArtefactNote(models.Model):
    artefact = models.ForeignKey(Artefact, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    record = models.ForeignKey(LogRecord, null=True, blank=True, on_delete=models.SET_NULL, related_name='referenced_in_notes')
    content = models.TextField()  # Use Markdown or RichText
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Note by {self.author} on {self.artefact.name}"
