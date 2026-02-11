from django.shortcuts import render,redirect
from django.contrib.auth import authenticate,login
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import UserProfile
from django.contrib import messages


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
    return redirect(request,'login.html')
  return render(request,'register.html')
  

@api_view(['POST'])
def login_view(request):
    username=request.data.get('username')
    password=request.data.get('password')
     
    user=authenticate(username=username,password=password)

    if user is None:
        return render(request,'login.html',{'error':'Invalid Credentials'},status=401)
    
    if user.account_status =='blocked':
        return render(request,'register.html',{'error':'Account is Blocked'},status=403)
    
    user.last_ip=request.META.get('REMOTE ADDRESS')
    user.last_device=request.META.get('HTTP_USER_AGENT')
    user.save()

    login(request,user)

    return render(request,'login.html',{'message':'Login Successful'})

