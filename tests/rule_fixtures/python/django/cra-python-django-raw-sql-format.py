from django.shortcuts import render


def search_fstring(request):
    name = request.GET["name"]
    # ruleid: cra-python-django-raw-sql-format
    qs = Person.objects.raw(f"SELECT * FROM app_person WHERE name = '{name}'")
    return render(request, "r.html", {"people": list(qs)})


def search_percent(request):
    name = request.GET["name"]
    # ruleid: cra-python-django-raw-sql-format
    qs = Person.objects.raw("SELECT * FROM app_person WHERE name = '%s'" % name)
    return render(request, "r.html", {"people": list(qs)})


def search_format(request):
    name = request.GET["name"]
    # ruleid: cra-python-django-raw-sql-format
    qs = Person.objects.raw("SELECT * FROM app_person WHERE name = '{}'".format(name))
    return render(request, "r.html", {"people": list(qs)})


def search_concat(request):
    name = request.GET["name"]
    # ruleid: cra-python-django-raw-sql-format
    qs = Person.objects.raw("SELECT * FROM app_person WHERE name = '" + name + "'")
    return render(request, "r.html", {"people": list(qs)})


def search_params(request):
    name = request.GET["name"]
    # ok: cra-python-django-raw-sql-format
    qs = Person.objects.raw("SELECT * FROM app_person WHERE name = %s", [name])
    return render(request, "r.html", {"people": list(qs)})


def search_literal(request):
    # ok: cra-python-django-raw-sql-format
    qs = Person.objects.raw("SELECT * FROM app_person")
    return render(request, "r.html", {"people": list(qs)})


def search_constant_fstring(request):
    # A constant f-string has no interpolation and is not injectable.
    # ok: cra-python-django-raw-sql-format
    qs = Person.objects.raw(f"SELECT * FROM app_person")
    return render(request, "r.html", {"people": list(qs)})
