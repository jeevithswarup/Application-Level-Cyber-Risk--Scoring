from django.shortcuts import render,redirect
from django.contrib.auth import authenticate,login
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import UserProfile


def Register(request):

  if request.method=='POST':
    username=request.data.get('username')
    password=request.data.get('password')
    confirm_password=request.data.get('confirm_password')
    email=request.data.get('email')

    if UserProfile.objects.filter(username=username).exists():
        return render(request,'register.html',{'error':'Username already exists'},status=400)
    
    if password!=confirm_password:
      return render(request,'register.html',
            {'error': 'Password do not match'},
            status=400 )

    user=UserProfile.objects.create_user(
        username=username,
        password=password,
        email=email,
     )
    return redirect(request,'login.html',{'message':'User is sucessfully Created'},status=201)
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

