from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt


def process(data):
    return data


@csrf_exempt
# ruleid: cra-python-django-csrf-exempt
def webhook(request):
    process(request.POST)
    return HttpResponse("ok")


@method_decorator(csrf_exempt, name="dispatch")
# ruleid: cra-python-django-csrf-exempt
class ApiView(View):
    def post(self, request):
        process(request.POST)
        return HttpResponse("ok")


def plain_view(request):
    process(request.POST)
    return HttpResponse("ok")

# ruleid: cra-python-django-csrf-exempt
urlpatterns_entry = csrf_exempt(plain_view)


# ok: cra-python-django-csrf-exempt
def guarded_view(request):
    process(request.POST)
    return HttpResponse("ok")
