from django.utils.html import format_html


def label_fstring(request):
    name = request.GET["name"]
    # ruleid: cra-python-django-format-html-interpolated
    return format_html(f"<span>{name}</span>")


def label_percent(request):
    name = request.GET["name"]
    # ruleid: cra-python-django-format-html-interpolated
    return format_html("<span>%s</span>" % name)


def label_strformat(request):
    name = request.GET["name"]
    # ruleid: cra-python-django-format-html-interpolated
    return format_html("<span>{}</span>".format(name))


def label_concat(request):
    name = request.GET["name"]
    # ruleid: cra-python-django-format-html-interpolated
    return format_html("<span>" + name + "</span>")


def label_placeholder(request):
    name = request.GET["name"]
    # ok: cra-python-django-format-html-interpolated
    return format_html("<span>{}</span>", name)


def label_multiple_args(request):
    first = request.GET["first"]
    last = request.GET["last"]
    # A static literal format string with the values passed as escaped
    # trailing arguments is the safe idiom.
    # ok: cra-python-django-format-html-interpolated
    return format_html("<span>{} {}</span>", first, last)
