from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="ciphers_index"),
    path("results/<str:hostname>", views.results, name="ciphers_results"),
]