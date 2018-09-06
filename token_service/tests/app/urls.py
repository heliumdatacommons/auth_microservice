from . import views

urlpatterns = [
    path('admin/key', views.create_key, name='create_key'),
]
