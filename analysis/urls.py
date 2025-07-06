from django.urls import path
from . import views
from analysis.ai import ai_artefact_analysis, ai_incident_analysis

app_name = "analysis"

urlpatterns = [
    # Start & Run Analysis
    path("", views.UnifiedDashboardView.as_view(), name="dashboard"),
    path("start/", views.AnalysisStartView.as_view(), name="start"),
    path("run/", views.run_analysis, name="run_analysis"),

    # Results Views
    path("artefact/<uuid:pk>/", views.ArtefactAnalysisResultView.as_view(), name="artefact_result"),
    path("incident/", views.IncidentAnalysisDashboardView.as_view(), name="results_by_incident"),


    path('analysis/ai/artefact/<uuid:artefact_id>/', ai_artefact_analysis, name='ai_artefact_analysis'),
    path('analysis/ai/incident/<slug:incident_id>/', ai_incident_analysis, name='ai_incident_analysis'),

]
