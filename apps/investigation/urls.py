from django.urls import path
from .views import (
    InvestigateByIOCView,
    InvestigateByIPView,
    InvestigateByDomainView,
    InvestigateByHashView,
)

urlpatterns = [
    path('ioc/<uuid:ioc_id>/', InvestigateByIOCView.as_view(), name='investigate-ioc'),
    path('ip/<str:ip>/', InvestigateByIPView.as_view(), name='investigate-ip'),
    path('domain/<str:domain>/', InvestigateByDomainView.as_view(), name='investigate-domain'),
    path('hash/<str:hash_value>/', InvestigateByHashView.as_view(), name='investigate-hash'),
]
