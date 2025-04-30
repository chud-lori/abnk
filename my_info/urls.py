from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("getEnv", views.getenv, name="getenv"),
    path("callback", views.callback, name="callback"),
    path("getPersonData", views.getpersondata, name="getpersondata"),
    path("generateCodeChallenge", views.gencode, name="gencode"),
]
