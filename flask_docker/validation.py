import re
from math import log2

def textValidation(text):
    pat = re.compile(r"^[a-zA-Z0-9]*$")
    if re.fullmatch(pat, text):
        return True
    else:
        return False

def passwordValidation(password):
    if not textValidation(password):
        return False
    pat = re.compile(
        r"(?=(.*[0-9]))((?=.*[A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z]))^.{8,16}$")
    if re.fullmatch(pat, password):
        return True
    else:
        return False

def nameValidation(login):
    pat = re.compile(r"^[a-zA-Z0-9]{2,16}$")
    if re.fullmatch(pat, login):
        return True
    else:
        return False

def emailValidation(email):
    pat = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    if re.fullmatch(pat, email):
        return True
    else:
        return False

def entropy(string):
    entropy = 0.0
    size = len(string)
    for i in range(256):
        prob = string.count(chr(i)) / size
        if prob > 0.0:
            entropy += prob * log2(prob)
    return -entropy
