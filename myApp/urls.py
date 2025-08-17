from django.urls import path
from myApp import views

urlpatterns = [
    # Portal
    path("prtal/", views.portal_home, name="portal_home"),
    path("portal/login/", views.portal_login, name="portal_login"),
    path("portal/logout/", views.portal_logout, name="portal_logout"),
    path("portal/<slug:slug>/", views.portal_dashboard, name="portal_dashboard"),
    path("portal/<slug:slug>/calendar/", views.portal_calendar, name="portal_calendar"),

    # Simple booking API
    path("api/<slug:slug>/resources/<int:resource_id>/bookings", views.list_bookings, name="list_bookings"),
    path("api/<slug:slug>/resources/<int:resource_id>/booking", views.create_booking, name="create_booking"),
    path("api/<slug:slug>/resources/<int:resource_id>/booking/delete", views.delete_booking, name="delete_booking"),


    # Resources management
    path("portal/<slug:slug>/resources/", views.portal_resources, name="portal_resources"),
    path("portal/<slug:slug>/resources/create", views.resource_create, name="resource_create"),
    path("portal/<slug:slug>/resources/<int:resource_id>/update", views.resource_update, name="resource_update"),
    path("portal/<slug:slug>/resources/<int:resource_id>/delete", views.resource_delete, name="resource_delete"),

    path("portal/<slug:slug>/resources/api", views.portal_api_resources, name="portal_api_resources"),
    path("portal/<slug:slug>/resources/api/<int:resource_id>", views.portal_api_resource_detail, name="portal_api_resource_detail"),

    # Messenger webhook (keep your implementation in views.py)
    path("messenger/<slug:slug>/webhook", views.webhook, name="messenger_webhook"),

    path("legal/privacy/", views.legal_privacy, name="legal_privacy"),
    path("legal/terms/", views.legal_terms, name="legal_terms"),
    path("legal/data-deletion/", views.legal_data_deletion, name="legal_data_deletion"),
    path("", views.about, name="about"),
    path("contact/", views.contact, name="contact"),
]
