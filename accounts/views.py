from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages

from .models import UserProfile, LoginActivity
from .utils import get_client_ip, get_device_info
from .risk_engine import (
    failed_login_risk,
    ip_device_change_risk,
    normal_behavior_reward
)


def Register(request):

    if request.method == 'POST':

        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        email = request.POST.get('email')

        if UserProfile.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, 'register.html')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'register.html')

        UserProfile.objects.create_user(
            username=username,
            password=password,
            email=email,
        )

        messages.success(request, "Account created successfully.")
        return redirect('login')

    return render(request, 'register.html')


def login_view(request):

    if request.method == 'POST':

        username = request.POST.get('username')
        password = request.POST.get('password')

        ip = get_client_ip(request)
        device = get_device_info(request)

        user = authenticate(request, username=username, password=password)

        # ✅ FAILED LOGIN
        if user is None:

            existing_user = UserProfile.objects.filter(username=username).first()

            if existing_user:
                failed_login_risk(existing_user)

            LoginActivity.objects.create(
                username_attempted=username,
                ip_address=ip,
                device_info=device,
                status='FAILED'
            )

            messages.error(request, "Invalid Credentials.")
            return render(request, 'login.html')

        # ✅ BLOCKED ACCOUNT
        if user.account_status == 'blocked':

            LoginActivity.objects.create(
                user=user,
                username_attempted=username,
                ip_address=ip,
                device_info=device,
                status='FAILED'
            )

            messages.error(request, "Account is Blocked.")
            return render(request, 'login.html')

        # ✅ IP / DEVICE CHANGE DETECTION
        if user.last_ip and user.last_ip != ip:
            ip_device_change_risk(user)

        if user.last_device and user.last_device != device:
            ip_device_change_risk(user)

        # ✅ NORMAL BEHAVIOR REWARD
        normal_behavior_reward(user)

        # ✅ UPDATE METADATA
        user.last_ip = ip
        user.last_device = device
        user.save()

        login(request, user)

        # ✅ LOG SUCCESS
        LoginActivity.objects.create(
            user=user,
            username_attempted=username,
            ip_address=ip,
            device_info=device,
            status='SUCCESS',
        )

        messages.success(request, "Login Successful.")
        # return redirect('dashboard')   # 🔥 IMPORTANT

    return render(request, 'login.html')
