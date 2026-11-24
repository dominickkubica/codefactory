import hashlib
import os
import random
import secrets
import subprocess

import requests
from django.db import connection
from django.http import JsonResponse

from .models import Profile, User

DEBUG = True


def search(request):
    q = request.GET["q"]
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM items WHERE title LIKE '%s'" % q)
        return JsonResponse(cursor.fetchall(), safe=False)


def detail(request, pk):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM items WHERE id = %s", [pk])
        return JsonResponse(cursor.fetchone(), safe=False)


def disk_usage(path):
    return subprocess.check_output("du -sh " + path, shell=True)


def clear_screen():
    os.system("clear")


def notify(url, data):
    return requests.post(url, json=data)


def store_password(password, salt):
    return hashlib.sha1((password + salt).encode()).hexdigest()


def otp_code():
    otp = random.randint(100000, 999999)
    return otp


def invite_token():
    return secrets.token_hex(16)


def parse_int(text):
    try:
        return int(text)
    except: pass


def parse_float(text):
    try:
        return float(text)
    except ValueError:
        return None


def profiles():
    out = []
    for user in User.objects.all():
        out.append(Profile.objects.get(user=user))
    return out


def welcome(user, count):
    print(f"new user {user.email}")
    print(f"emailing {count} users")
