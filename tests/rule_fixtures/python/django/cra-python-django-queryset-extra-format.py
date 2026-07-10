def listing_where_fstring(request):
    status = request.GET["status"]
    # ruleid: cra-python-django-queryset-extra-format
    return Order.objects.extra(where=[f"status = '{status}'"])


def listing_where_percent(request):
    status = request.GET["status"]
    # ruleid: cra-python-django-queryset-extra-format
    return Order.objects.extra(where=["status = '%s'" % status])


def listing_where_concat(request):
    status = request.GET["status"]
    # ruleid: cra-python-django-queryset-extra-format
    return Order.objects.extra(where=["status = '" + status + "'"])


def listing_select_format(request):
    expr = request.GET["expr"]
    # ruleid: cra-python-django-queryset-extra-format
    return Order.objects.extra(select={"is_recent": "created > '{}'".format(expr)})


def listing_order_by_fstring(request):
    col = request.GET["col"]
    # ruleid: cra-python-django-queryset-extra-format
    return Order.objects.extra(order_by=[f"{col}"])


def listing_params(request):
    status = request.GET["status"]
    # ok: cra-python-django-queryset-extra-format
    return Order.objects.extra(where=["status = %s"], params=[status])


def listing_literal():
    # ok: cra-python-django-queryset-extra-format
    return Order.objects.extra(where=["is_active = 1"])


def listing_constant_fstring():
    # A constant f-string has no interpolation and is not injectable.
    # ok: cra-python-django-queryset-extra-format
    return Order.objects.extra(where=[f"is_active = 1"])
