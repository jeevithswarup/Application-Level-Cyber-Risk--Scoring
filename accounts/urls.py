from django.urls import path
from .views import *

urlpatterns = [
     path('register/',Register,name="Register"),
     path('login/',login_view,name='login_view'),
     path('',home),
]
