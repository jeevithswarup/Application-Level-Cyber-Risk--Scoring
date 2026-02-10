from rest_framework import serializers
from .models import UserProfile



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=UserProfile
        fields=[
            'id',
            'username',
            'email',
            'role',
            'risk_score',
            'account_status',
            'last_ip',
            'last_device',
        ]
        read_only_fields = ['risk_score', 'last_ip', 'last_device']