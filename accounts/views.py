from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required

from .models import UserProfile, LoginActivity, BehaviorLog

from .utils import get_client_ip, get_device_info

from .risk_engine import (
    failed_login_risk,
    ip_device_change_risk,
    normal_behavior_reward
)


# -------------------------
# LOGOUT
# -------------------------

def logout_view(request):

    logout(request)

    return redirect('login')


# -------------------------
# REGISTER
# -------------------------

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
            messages.error(request, "Passwords do not match.")
            return render(request, 'register.html')

        UserProfile.objects.create_user(
            username=username,
            password=password,
            email=email
        )

        messages.success(request, "Account created successfully.")
        return redirect('login')

    return render(request, 'register.html')


# -------------------------
# LOGIN
# -------------------------

def login_view(request):

    if request.method == 'POST':

        username = request.POST.get('username')
        password = request.POST.get('password')

        ip = get_client_ip(request)
        device = get_device_info(request)

        user = authenticate(request, username=username, password=password)

        # -------------------------
        # FAILED LOGIN
        # -------------------------

        if user is None:

            existing_user = UserProfile.objects.filter(username=username).first()

            if existing_user:

                # increase failed attempts
                existing_user.failed_attempts += 1

                # apply risk engine
                failed_login_risk(existing_user)

                # BRUTE FORCE DETECTION
                if existing_user.failed_attempts >= 5:
                    existing_user.account_status = "restricted"
                    existing_user.risk_score += 10

                # AUTO BLOCK IF RISK TOO HIGH
                if existing_user.risk_score > 80:
                    existing_user.account_status = "blocked"

                existing_user.save()

            LoginActivity.objects.create(
                username_attempted=username,
                ip_address=ip,
                device_info=device,
                status='FAILED'
            )

            messages.error(request, "Invalid Credentials.")
            return render(request, 'login.html')

        # -------------------------
        # BLOCKED ACCOUNT CHECK
        # -------------------------

        if user.account_status == 'blocked':

            LoginActivity.objects.create(
                user=user,
                username_attempted=username,
                ip_address=ip,
                device_info=device,
                status='FAILED'
            )

            messages.error(request, "Account is blocked due to high cyber risk.")
            return render(request, 'login.html', status=403)

        # -------------------------
        # IP / DEVICE CHANGE DETECTION
        # -------------------------

        if user.last_ip and user.last_ip != ip:
            ip_device_change_risk(user)

        if user.last_device and user.last_device != device:
            ip_device_change_risk(user)

        # -------------------------
        # NORMAL BEHAVIOR REWARD
        # -------------------------

        normal_behavior_reward(user)

        # -------------------------
        # RESET FAILED ATTEMPTS
        # -------------------------

        user.failed_attempts = 0

        # update device metadata
        user.last_ip = ip
        user.last_device = device

        user.save()

        # login session
        login(request, user)

        LoginActivity.objects.create(
            user=user,
            username_attempted=username,
            ip_address=ip,
            device_info=device,
            status='SUCCESS'
        )

        messages.success(request, "Login Successful")

        return redirect('dashboard')

    return render(request, 'login.html')


# -------------------------
# DASHBOARD
# -------------------------

@login_required
def dashboard(request):

    user = request.user

    login_logs = LoginActivity.objects.filter(user=user).order_by('-timestamp')[:10]
    behavior_logs = BehaviorLog.objects.filter(user=user).order_by('-timestamp')[:10]

    risk_score = user.risk_score

    context = {
        "user": user,
        "login_logs": login_logs,
        "behavior_logs": behavior_logs,
        "risk_score": risk_score
    }

    return render(request, "dashboard.html", context)


# -------------------------
# LIVE RISK MONITOR API
# -------------------------

@login_required
def risk_monitor_api(request):

    user = request.user

    data = {

        "risk_score": user.risk_score,
        "account_status": user.account_status,
        "failed_attempts": user.failed_attempts,
        "last_ip": user.last_ip

    }

    return JsonResponse(data)