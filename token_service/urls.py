"""
token_service URL Configuration

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
try:
    from django.urls import url
except ImportError:
    from django.conf.urls import url

from . import views

urlpatterns = [
    url('^$', views.index),

    # admin (requires admin key)
    url('^admin/key/?$', views.create_key, name='create_key'),
    # public
    url('^subject_by_nonce/?$', views.subject_by_nonce, name='subject_by_nonce'),
    url('^authorize/?$', views.url, name='url'),
    url('^authcallback/?$', views.authcallback, name='authcallback'),

    # private token operations (protected by api key)
    url('^token/?$', views.token, name='token'),
    url('^validate_token/?$', views.validate_token, name='validate_token'),

    # api keys
    url('^apikey/verify/?$', views.verify_user_key),  # must be before uid urls to avoid shadowing
    url('^apikey/(?P<uid>[^/]+)/?$', views.list_user_keys),
    url('^apikey/(?P<uid>[^/]+)/new/?$', views.new_user_key),
    url('^apikey/(?P<uid>[^/]+)/(?P<key_id>[^/]+)/?$', views.action_user_key),

]
