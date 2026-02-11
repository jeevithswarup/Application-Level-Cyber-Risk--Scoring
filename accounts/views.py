from django.shortcuts import render,redirect
from django.contrib.auth import authenticate,login
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import UserProfile
from django.contrib import messages
from .models import LoginActivity
from .utils import get_client_ip, get_device_info

def Register(request):

  if request.method=='POST':
    username=request.POST.get('username')
    password=request.POST.get('password')
    confirm_password=request.POST.get('confirm_password')
    email=request.POST.get('email')

    if UserProfile.objects.filter(username=username).exists():
        messages.error(request, "Username already exists.")
        return render(request,'register.html')
    
    if password!=confirm_password:
      messages.error(request, 'Password do not match')
      return render(request,'register.html')

    user=UserProfile.objects.create_user(
        username=username,
        password=password,
        email=email,
     )
    messages.success(request, "Account created successfully.")
    return redirect('login')
  return render(request,'register.html')
  


def login_view(request):
   if  request.method=='POST':
        username=request.POST.get('username')
        password=request.POST.get('password')
        
        user=authenticate(username=username,password=password)

        ip = get_client_ip(request)
        device = get_device_info(request)

        if user is None:
          LoginActivity.objects.create( username_attempted=username,ip_address=ip,device_info=device,status='FAILED')

          messages.error(request, "Invalid Credentials.")
          return render(request,'login.html')
        
        if user.account_status =='blocked':
            LoginActivity.objects.create(
                user=user,
                username_attempted=username,
                ip_address=ip,
                device_info=device,
                status='FAILED'
            )
            messages.error(request, "Account is Blocked.")
            return render(request,'login.html',status=403)
        
        user.last_ip = ip
        user.last_device = device
        user.save()

        login(request,user)
        LoginActivity.objects.create(
            user=user,
            username_attempted=username,
            ip_address=ip,
            device_info=device,
            status='SUCCESS'
        )
        messages.success(request, "Login Successful")
   return render(request,'login.html')

