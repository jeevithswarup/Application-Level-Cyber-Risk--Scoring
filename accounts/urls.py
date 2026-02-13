from django.urls import path
from .views import *

urlpatterns = [
     path('',Register,name="Register"),
     path('login/',login_view,name='login'),
     path('dashboard/',dashboard,name="dashboard"),
    
]
