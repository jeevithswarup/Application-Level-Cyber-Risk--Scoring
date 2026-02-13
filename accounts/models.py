from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings

class UserProfile(AbstractUser):
    ROLE_CHOICES = (
        ('user', 'User'),
        ('admin', 'Admin'),
    )
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('restricted', 'Restricted'),
        ('blocked', 'Blocked'),
    )

    role=models.CharField(max_length=10,choices=ROLE_CHOICES,default='user')

    
    risk_score=models.IntegerField(default=0)
    last_ip = models.GenericIPAddressField(null=True,blank=True)
    last_device=models.TextField(null=True,blank=True)
    account_status=models.CharField(max_length=15,choices=STATUS_CHOICES,default='active')
    failed_attempts = models.IntegerField(default=0)

    def __str__(self):
        return self.username

class LoginActivity(models.Model):

    STATUS_CHOICES = (
        ('SUCCESS', 'Success'),
        ('FAILED', 'Failed'),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )

    username_attempted = models.CharField(max_length=150)

    ip_address = models.GenericIPAddressField(null=True, blank=True)

    device_info = models.TextField(null=True, blank=True)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES)

    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.username_attempted} - {self.status}"


    

        
