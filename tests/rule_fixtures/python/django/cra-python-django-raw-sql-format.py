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


def search_variable_fstring(request):
    name = request.GET["name"]
    query = f"SELECT * FROM app_person WHERE name = '{name}'"
    # ruleid: cra-python-django-raw-sql-format
    qs = Person.objects.raw(query)
    return render(request, "r.html", {"people": list(qs)})


def search_variable_percent(request):
    name = request.POST["name"]
    query = "SELECT * FROM app_person WHERE name = '%s'" % name
    # ruleid: cra-python-django-raw-sql-format
    qs = Person.objects.raw(query)
    return render(request, "r.html", {"people": list(qs)})


def search_variable_format(request):
    name = request.query_params["name"]
    query = "SELECT * FROM app_person WHERE name = '{}'".format(name)
    # ruleid: cra-python-django-raw-sql-format
    qs = Person.objects.raw(query)
    return render(request, "r.html", {"people": list(qs)})


def search_variable_concat(request):
    name = request.GET.get("name", "")
    query = "SELECT * FROM app_person WHERE name = '" + name + "'"
    # ruleid: cra-python-django-raw-sql-format
    qs = Person.objects.raw(query)
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


def search_params_keyword(request):
    name = request.GET["name"]
    # ok: cra-python-django-raw-sql-format
    qs = Person.objects.raw("SELECT * FROM app_person WHERE name = %s", params=[name])
    return render(request, "r.html", {"people": list(qs)})


def search_params_dict(request):
    name = request.POST["name"]
    # ok: cra-python-django-raw-sql-format
    qs = Person.objects.raw(
        "SELECT * FROM app_person WHERE name = %(name)s", {"name": name}
    )
    return render(request, "r.html", {"people": list(qs)})


def search_literal_concat(request):
    # Both operands are literals, so the query carries no untrusted input.
    query = "SELECT * FROM " + "app_person"
    # ok: cra-python-django-raw-sql-format
    qs = Person.objects.raw(query)
    return render(request, "r.html", {"people": list(qs)})


def search_constant_table(request):
    table = "app_person"
    # ok: cra-python-django-raw-sql-format
    qs = Person.objects.raw(f"SELECT * FROM {table}")
    return render(request, "r.html", {"people": list(qs)})
