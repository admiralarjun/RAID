from django.urls import path
from . import views

app_name = "analysis"

urlpatterns = [
    # Start & Run Analysis
    path("", views.UnifiedDashboardView.as_view(), name="dashboard"),
    path("start/", views.AnalysisStartView.as_view(), name="start"),
    path("run/", views.run_analysis, name="run_analysis"),

    # Results Views
    path("artefact/<uuid:pk>/", views.ArtefactAnalysisResultView.as_view(), name="artefact_result"),
    path("incident/", views.IncidentAnalysisDashboardView.as_view(), name="results_by_incident"),
]
