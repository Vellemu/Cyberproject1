from django.urls import path
from django.contrib import admin

from . import views

urlpatterns = [
    path('', views.homeView, name="homeView"),
    path('register/', views.registerView, name="registerView"),
    path('login/', views.loginView, name="loginView"),
    path('addSecret/', views.addSecret, name="addSecret"),
    path('logout/', views.logoutView, name="logout"),
    path('deleteSecret/<str:secret>/', views.deleteSecret, name="deleteSecret"),
]