import io
import json
import pickle


# Branch 1: pickle.loads()
def bad_pickle_loads(data: bytes):
    # ruleid: cra-python-pickle-loads
    return pickle.loads(data)


# Branch 2: pickle.load() from file-like object
def bad_pickle_load(fp: io.BytesIO):
    # ruleid: cra-python-pickle-loads
    return pickle.load(fp)


# Safe: json.loads does not deserialize arbitrary objects
def ok_json_loads(data: bytes):
    # ok: cra-python-pickle-loads
    return json.loads(data)


# Safe: json.load from file
def ok_json_load(fp):
    # ok: cra-python-pickle-loads
    return json.load(fp)
