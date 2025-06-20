from django.contrib import admin
from .models import UserProfile, Client, Incident

admin.site.register(UserProfile)
admin.site.register(Client)
admin.site.register(Incident)
