from django.db import models
from django.contrib.auth.models import AbstractUser

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
    
    def __str__(self):
        return self.username
    

        
