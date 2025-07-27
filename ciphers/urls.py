from django.urls import path
from ciphers import views

urlpatterns = [
    path('', views.index, name='index')
]
