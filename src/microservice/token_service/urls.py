"""microservice URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from . import views

urlpatterns = [
    path('admin/key', views.create_key, name='create_key'),
    # public
    path('subject_by_nonce', views.subject_by_nonce, name='subject_by_nonce'),
    path('authorize', views.url, name='url'),
    path('authcallback', views.authcallback, name='authcallback'),

    # private (protected by api key)
    path('token', views.token, name='token'),
    path('validate', views.validate_token, name='validate_token'),
]


