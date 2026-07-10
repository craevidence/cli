from django.db.models import RawSQL


def annotate_fstring(request):
    col = request.GET["sort"]
    # ruleid: cra-python-django-rawsql-expression
    return Article.objects.annotate(val=RawSQL(f"SELECT {col} FROM app_article", ()))


def annotate_percent(request):
    col = request.GET["sort"]
    # ruleid: cra-python-django-rawsql-expression
    return Article.objects.annotate(val=RawSQL("SELECT %s FROM app_article" % col, ()))


def annotate_format(request):
    col = request.GET["sort"]
    # ruleid: cra-python-django-rawsql-expression
    return Article.objects.annotate(val=RawSQL("SELECT {} FROM app_article".format(col), ()))


def annotate_concat(request):
    col = request.GET["sort"]
    # ruleid: cra-python-django-rawsql-expression
    return Article.objects.annotate(val=RawSQL("SELECT " + col + " FROM app_article", ()))


def annotate_params(pk):
    # ok: cra-python-django-rawsql-expression
    return Article.objects.annotate(val=RawSQL("SELECT weight FROM app_article WHERE id = %s", (pk,)))


def annotate_literal():
    # ok: cra-python-django-rawsql-expression
    return Article.objects.annotate(val=RawSQL("SELECT weight FROM app_article", ()))


def annotate_constant_fstring():
    # A constant f-string has no interpolation and is not injectable.
    # ok: cra-python-django-rawsql-expression
    return Article.objects.annotate(val=RawSQL(f"SELECT weight FROM app_article", ()))
