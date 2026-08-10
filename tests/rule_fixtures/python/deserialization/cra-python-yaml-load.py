import yaml


# Bad: yaml.load with no Loader argument
def bad_yaml_load(data: str):
    # ruleid: cra-python-yaml-load
    return yaml.load(data)


def bad_yaml_explicit_loader(data: str):
    # ruleid: cra-python-yaml-load
    return yaml.load(data, Loader=yaml.Loader)


def bad_yaml_explicit_unsafe_loader(data: str):
    # ruleid: cra-python-yaml-load
    return yaml.load(data, Loader=yaml.UnsafeLoader)


# Safe: yaml.safe_load restricts to basic types
def ok_yaml_safe_load(data: str):
    # ok: cra-python-yaml-load
    return yaml.safe_load(data)


# Safe: yaml.load with explicit SafeLoader
def ok_yaml_load_safe_loader(data: str):
    # ok: cra-python-yaml-load
    return yaml.load(data, Loader=yaml.SafeLoader)
