"""
Django settings for hirework_backend project.

Generated by 'django-admin startproject' using Django 5.0.4.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'error_file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': 'hirework_django_logs/error_logs.txt',  # Update this with your desired log file path
            'formatter': 'standard',
        },
        'info_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'hirework_django_logs/info_logs.txt',  # Update this with your desired log file path
            'formatter': 'standard',
        },
    },
    'loggers': {
        '': {
            'handlers': ['error_file', 'info_file'],
            'level': 'INFO',  # Set the root logger level to INFO to include INFO level logs
            'propagate': True,
        },
    },
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        },
    },
}



BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-ec$97(t0b(kskkh^pl!5#d+d@ur*eei3rkn)h&pylahr3w&&hm'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ["127.0.0.1", "13.234.33.63", "localhost"]
# ALLOWED_HOSTS = ["127.0.0.1", "13.234.33.63", "localhost", "www.hirework.co.in", "hirework.co.in", "https://hirework.co.in"]
# CSRF_TRUSTED_ORIGINS = ["http://13.234.33.63", "https://hirework.co.in" , "https://www.hirework.co.in", "http://localhost", "http://127.0.0.1", "https://localhost", "https://127.0.0.1", "http://[::1]",  "https://[::1]", "https://49.37.176.112", "http://49.37.176.112"]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'hirework',
    'rest_framework',
    'corsheaders'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'corsheaders.middleware.CorsMiddleware'
]

ROOT_URLCONF = 'hirework_backend.urls'

CORS_ALLOW_ALL_ORIGINS = True

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "http://13.234.33.63",
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'hirework_backend.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

# STATIC_URL = 'static/'


# For Server : 
# STATIC_URL = 'static/'
# MEDIA_ROOT = '/var/www/html/hirework_venv/hirework_backend/hirework/uploads/'
# STATIC_ROOT = '/var/www/html/hirework_venv/hirework_backend/static'

# For Local : 
STATIC_URL = 'hirework/uploads/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'hirework/uploads'),
]

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
# AUTH_USER_MODEL = 'hirework.UserModel'

# 00000000000000000000000000000000000000000000000000000000000000000000000
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
EMAIL_HOST = 'mail.capace.co.in'
EMAIL_PORT = 465
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False 

EMAIL_HOST_USER = 'testing@capace.co.in'
EMAIL_HOST_PASSWORD = 'capace@312'
# 00000000000000000000000000000000000000000000000000000000000000000000000
