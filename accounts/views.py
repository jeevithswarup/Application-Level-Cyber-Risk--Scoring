import random
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .utils import get_location_from_ip
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
# LOGIN (WITH CAPTCHA + OTP)
def login_view(request):

    show_captcha = False
    show_otp = False

    # Generate CAPTCHA numbers
    if 'num1' not in request.session:
        request.session['num1'] = random.randint(1, 9)
        request.session['num2'] = random.randint(1, 9)

    num1 = request.session['num1']
    num2 = request.session['num2']

    if request.method == 'POST':

        username = request.POST.get('username')
        password = request.POST.get('password')
        entered_captcha = request.POST.get('captcha')
        entered_otp = request.POST.get('otp')

        ip = get_client_ip(request)
        device = get_device_info(request)

        existing_user = UserProfile.objects.filter(username=username).first()

        # ---------------- PRIORITY LOGIC ----------------

        if existing_user:

            # 🔴 BLOCK
            if existing_user.risk_score > 80:
                existing_user.account_status = "blocked"
                existing_user.save()
                messages.error(request, "Account Blocked due to high risk")
                return render(request, 'login.html')

            # 🔐 OTP
            if existing_user.risk_score > 60:
                show_otp = True

            # 🧠 CAPTCHA
            elif existing_user.failed_attempts >= 3:
                show_captcha = True

        # ---------------- CAPTCHA VALIDATION ----------------

        if show_captcha:
            correct_answer = num1 + num2

            if not entered_captcha or int(entered_captcha) != correct_answer:
                messages.error(request, "Invalid CAPTCHA")
                return render(request, 'login.html', {
                    "show_captcha": True,
                    "num1": num1,
                    "num2": num2
                })

        # ---------------- OTP VALIDATION ----------------

        if show_otp:

            # First time → generate OTP
            if not request.session.get('otp_required'):
                otp = str(random.randint(100000, 999999))

                request.session['otp'] = otp
                request.session['otp_user'] = username
                request.session['otp_required'] = True

                print("OTP:", otp)

                messages.warning(request, "Enter OTP to continue")

                return render(request, 'login.html', {
                    "show_otp": True,
                    "num1": num1,
                    "num2": num2
                })

            # Verify OTP
            real_otp = request.session.get('otp')

            if entered_otp == real_otp:

                user = UserProfile.objects.get(username=username)
                login(request, user)

                request.session.flush()

                return redirect('dashboard')

            else:
                messages.error(request, "Invalid OTP")
                return render(request, 'login.html', {
                    "show_otp": True,
                    "num1": num1,
                    "num2": num2
                })

        # ---------------- AUTHENTICATION ----------------

        user = authenticate(request, username=username, password=password)

        # ---------------- FAILED LOGIN ----------------

        if user is None:

            if existing_user:
                existing_user.failed_attempts += 1
                failed_login_risk(existing_user)

                if existing_user.failed_attempts >= 5:
                    existing_user.account_status = "restricted"

                if existing_user.risk_score > 80:
                    existing_user.account_status = "blocked"

                existing_user.save()

            location = get_location_from_ip(ip)

            LoginActivity.objects.create(
                user=user,
                username_attempted=username,
                ip_address=ip,
                device_info=device,
                location=location,
                status='SUCCESS'
            )

            messages.error(request, "Invalid Credentials")

            return render(request, 'login.html', {
                "show_captcha": show_captcha,
                "num1": num1,
                "num2": num2
            })

        # ---------------- NORMAL LOGIN ----------------

        if user.last_ip and user.last_ip != ip:
            ip_device_change_risk(user)

        if user.last_device and user.last_device != device:
            ip_device_change_risk(user)

        normal_behavior_reward(user)

        user.failed_attempts = 0
        user.last_ip = ip
        user.last_device = device
        user.save()

        login(request, user)

        LoginActivity.objects.create(
            user=user,
            username_attempted=username,
            ip_address=ip,
            device_info=device,
            status='SUCCESS'
        )

        return redirect('dashboard')

    return render(request, 'login.html', {
        "show_captcha": show_captcha,
        "show_otp": show_otp,
        "num1": num1,
        "num2": num2
    })
# -------------------------
# OTP VERIFY
# -------------------------
def otp_verify(request):

    if request.method == "POST":

        entered_otp = request.POST.get("otp")
        real_otp = request.session.get("otp")

        if entered_otp == real_otp:

            username = request.session.get("otp_user")
            user = UserProfile.objects.get(username=username)

            login(request, user)

            return redirect("dashboard")

        else:
            messages.error(request, "Invalid OTP")

    return render(request, "otp.html")


# -------------------------
# DASHBOARD
# -------------------------
@login_required
def dashboard(request):

    user = request.user

    login_logs = LoginActivity.objects.filter(user=user).order_by('-timestamp')[:10]
    behavior_logs = BehaviorLog.objects.filter(user=user).order_by('-timestamp')[:10]

    context = {
        "user": user,
        "login_logs": login_logs,
        "behavior_logs": behavior_logs,
        "risk_score": user.risk_score
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