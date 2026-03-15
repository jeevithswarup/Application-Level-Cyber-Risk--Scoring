from django.contrib import admin
from .models import *
from django.utils.html import format_html



class UserProfileAdmin(admin.ModelAdmin):

    list_display = (
        'username',
        'email',
        'risk_score',
        'colored_status',
        'failed_attempts',
        'last_ip'
    )

    list_filter = ('account_status',)

    search_fields = ('username', 'email', 'last_ip')

    ordering = ('-risk_score',)

    def colored_status(self, obj):

        if obj.account_status == "blocked":
            return format_html('<span style="color:red; font-weight:bold;">Blocked</span>')

        elif obj.account_status == "restricted":
            return format_html('<span style="color:orange; font-weight:bold;">Restricted</span>')

        else:
            return format_html('<span style="color:green; font-weight:bold;">Active</span>')

    colored_status.short_description = "Account Status"


admin.site.register(UserProfile, UserProfileAdmin)
admin.site.register(LoginActivity)
admin.site.register(BehaviorLog)