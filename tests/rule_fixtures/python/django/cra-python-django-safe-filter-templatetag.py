from django import template
from django.utils.html import format_html
from django.utils.safestring import mark_safe

register = template.Library()


@register.filter(is_safe=True)
def wrap_fstring(value):
    # ruleid: cra-python-django-safe-filter-templatetag
    return mark_safe(f"<em>{value}</em>")


@register.filter
def wrap_concat(value):
    # ruleid: cra-python-django-safe-filter-templatetag
    return mark_safe("<em>" + value + "</em>")


@register.simple_tag
def tag_percent(value):
    # ruleid: cra-python-django-safe-filter-templatetag
    return mark_safe("<em>%s</em>" % value)


@register.simple_tag(takes_context=True)
def tag_strformat(context, value):
    # ruleid: cra-python-django-safe-filter-templatetag
    return mark_safe("<em>{}</em>".format(value))


@register.filter
def wrap_format_html(value):
    # ok: cra-python-django-safe-filter-templatetag
    return format_html("<em>{}</em>", value)


@register.filter
def wrap_escaped(value):
    from django.utils.html import escape
    # ok: cra-python-django-safe-filter-templatetag
    return mark_safe("<em>{}</em>".format(escape(value)))


@register.filter(is_safe=True)
def wrap_constant_fstring(value):
    # A constant f-string has no interpolation and is not injectable.
    # ok: cra-python-django-safe-filter-templatetag
    return mark_safe(f"<em>static</em>")


@register.filter(is_safe=True)
def wrap_constant(value):
    # ok: cra-python-django-safe-filter-templatetag
    return mark_safe("<em>static</em>")


def helper_fstring(value):
    # ok: cra-python-django-safe-filter-templatetag
    return mark_safe(f"<em>{value}</em>")
