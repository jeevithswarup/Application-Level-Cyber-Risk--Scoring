from django.shortcuts import render
from django.contrib.auth import authenticate,login
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import UserProfile


@api_view(['POST'])
def Register(request):
    username=request.data.get('username')
    password=request.data.get('password')
    email=request.data.get('email')

    if UserProfile.objects.filter(username=username).exists():
        return Response({'error':'Username already exists'},status=400)
    
    user=UserProfile.objects.create_user(
        username=username,
        password=password,
        email=email,
    )
    return Response({'message':'User is sucessfully Created'})


