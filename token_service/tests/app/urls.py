from token_service import views
try:
    from django.urls import url
except ImportError:
    from django.conf.urls import url

urlpatterns = [
    url('^admin/key$', views.create_key, name='create_key'),
]
