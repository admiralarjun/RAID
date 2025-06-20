from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [

    # Dashboard URL
    path('', views.DashboardView.as_view(), name='dashboard'),

    # Incident URLs
    path('incidents/', views.IncidentListView.as_view(), name='incident_list'),
    path('incidents/new/', views.IncidentCreateView.as_view(), name='incident_create'),
    path('incidents/<slug:incident_id>/', views.IncidentDetailView.as_view(), name='incident_detail'),
    path('incidents/<int:pk>/edit/', views.IncidentUpdateView.as_view(), name='incident_update'),
    path('incidents/<int:pk>/delete/', views.IncidentDeleteView.as_view(), name='incident_delete'),
    
    # Client URLs
    path('clients/', views.ClientListView.as_view(), name='client_list'),
    path('clients/new/', views.ClientCreateView.as_view(), name='client_create'),
    path('clients/<int:pk>/', views.ClientDetailView.as_view(), name='client_detail'),
    path('clients/<int:pk>/edit/', views.ClientUpdateView.as_view(), name='client_update'),
    path('clients/<int:pk>/delete/', views.ClientDeleteView.as_view(), name='client_delete'),

    # UserProfile URLs
    path('profiles/', views.UserProfileListView.as_view(), name='profile_list'),
    path('profiles/<int:pk>/edit/', views.UserProfileUpdateView.as_view(), name='profile_update'),

    path('artefacts/', views.ArtefactListView.as_view(), name='artefact_list'),
    path('artefacts/new/', views.ArtefactUploadView.as_view(), name='artefact_create'),
    path('artefacts/<uuid:pk>/', views.ArtefactDetailView.as_view(), name='artefact_detail'),
    path('artefacts/<uuid:pk>/edit/', views.ArtefactUpdateView.as_view(), name='artefact_update'),
    path('artefacts/<uuid:pk>/delete/', views.ArtefactDeleteView.as_view(), name='artefact_delete'),

    # === Log Records & Notes ===
    path('logs/<int:pk>/', views.LogRecordPermalinkView.as_view(), name='log_record_permalink'),
    path('artefacts/add-note/', views.AddArtefactNoteView.as_view(), name='add_artefact_note'),
]