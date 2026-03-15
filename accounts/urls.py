from django.urls import path
from .views import *

urlpatterns = [
     path('',Register,name="register"),
     path('login/',login_view,name='login'),
     path('logout/',logout_view,name='logout'),
     path('dashboard/', dashboard, name='dashboard'),
     path('risk-monitor/', risk_monitor_api, name='risk_monitor')
]
