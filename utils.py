import re

def clean(t):
    t = str(t).lower()
    t = re.sub(r"http\S+|www\.\S+", " url ", t)
    t = re.sub(r"\d+", " num ", t)
    t = re.sub(r"[^a-z\s]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t