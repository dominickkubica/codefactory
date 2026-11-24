import os

DEBUG = os.environ.get("DEBUG") == "1"
CORS_ALLOW_ALL_ORIGINS = True
SECRET_KEY = os.environ["SECRET_KEY"]
CSRF_COOKIE_SECURE = True
