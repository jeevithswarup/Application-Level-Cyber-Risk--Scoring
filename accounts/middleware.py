from .models import BehaviorLog


class BehaviorMonitoringMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response


    def __call__(self, request):

        if request.user.is_authenticated:

            BehaviorLog.objects.create(
                user=request.user,
                path=request.path,
                ip_address=request.META.get("REMOTE_ADDR")
            )

        response = self.get_response(request)

        return response