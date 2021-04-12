import xml.sax
from hashlib import md5

def func1():
    test_digest = md5("test string").digest()
    return test_digest

def func2():  # double vulnerability
    test_digesta, test_digestb = md5("test string").digest(), md5("test string2").digest()
    return test_digesta, test_digestb

def func3(val):
    assert 0 != val
    return val / 3
