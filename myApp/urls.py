from . import views
from django.urls import path

urlpatterns = [
    path('', views.index, name='index'),
    path('webhook/', views.webhook, name='messenger_webhook'),
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.custom_logout_view, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),

]
