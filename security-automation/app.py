"""Deliberately insecure sample used to demonstrate security-scan. Do not deploy."""
import os
import pickle
import subprocess

API_KEY = "sk_live_abcdef123456"


def handle(user_input, blob):
    eval(user_input)
    os.system("ls " + user_input)
    subprocess.run(user_input, shell=True)
    return pickle.loads(blob)
