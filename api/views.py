from django.http import JsonResponse

def get_home_data(request):
    data = {
        'message': 'Hello from Django backend!'
    }
    return JsonResponse(data)