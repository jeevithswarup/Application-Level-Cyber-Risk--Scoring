import requests


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')

    return ip


def get_device_info(request):
    return request.META.get('HTTP_USER_AGENT')


def get_location_from_ip(ip):
    try:
        # 🚨 Handle localhost case
        if ip in ["127.0.0.1", "localhost"]:
            return "Localhost (Development)"

        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()

        # 🛡 Handle API failure
        if data['status'] != 'success':
            return "Unknown Location"

        city = data.get('city', '')
        country = data.get('country', '')

        return f"{city}, {country}"

    except Exception as e:
        return "Unknown Location"