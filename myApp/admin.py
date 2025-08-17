# messenger_bot/admin.py
from django.contrib import admin
from django import forms
from django.utils.html import format_html
from .models import (
    Business, BusinessMember, Snippet,
    Resource, OpeningRule, DayOverride, SlotOverride, Booking
)
import secrets


# --------------------------
# Forms
# --------------------------
class BusinessForm(forms.ModelForm):
    # keep secrets masked in the form (you can still paste/replace)
    fb_page_access_token = forms.CharField(
        widget=forms.PasswordInput(render_value=True)
    )
    fb_app_secret = forms.CharField(
        widget=forms.PasswordInput(render_value=True)
    )

    class Meta:
        model = Business
        fields = "__all__"


# --------------------------
# Admins
# --------------------------
@admin.register(Business)
class BusinessAdmin(admin.ModelAdmin):
    form = BusinessForm

    list_display = (
        "name", "slug", "model_name", "manage_token_short",
        "availability_provider", "updated_at",
    )
    search_fields = ("name", "slug", "system_prompt", "business_context")
    readonly_fields = ("created_at", "updated_at")
    list_filter = ("availability_provider",)

    fieldsets = (
        ("Identity", {"fields": ("name", "slug", "timezone")}),
        ("Messenger Credentials", {
            "fields": ("fb_page_access_token", "fb_verify_token", "fb_app_secret"),
            "description": "Use Page Access Token (not app token).",
        }),
        ("AI Config", {"fields": ("model_name", "temperature", "max_tokens")}),
        ("Prompt Stack", {"fields": ("system_prompt", "business_context")}),
        ("UX / Guardrails", {"fields": ("quick_replies", "blocked_keywords")}),
        ("Management & Availability", {
            "fields": ("manage_token", "availability_provider", "availability_config"),
            "description": (
                "manage_token = simple API key used by the calendar UI. "
                "Click the admin action “Generate manage token” to create one."
            ),
        }),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )

    @admin.display(description="Manage token")
    def manage_token_short(self, obj: Business):
        if not obj.manage_token:
            return format_html('<span style="color:#c00">— none —</span>')
        t = obj.manage_token
        # show a short preview only
        return f"{t[:6]}…{t[-4:]}"

    # Handy admin actions
    @admin.action(description="Generate manage token")
    def generate_manage_token(self, request, queryset):
        for biz in queryset:
            biz.manage_token = secrets.token_urlsafe(32)
            biz.save()
        self.message_user(request, f"Generated token for {queryset.count()} business(es).")

    @admin.action(description="Clear manage token")
    def clear_manage_token(self, request, queryset):
        for biz in queryset:
            biz.manage_token = ""
            biz.save()
        self.message_user(request, f"Cleared token for {queryset.count()} business(es).")

    actions = ["generate_manage_token", "clear_manage_token"]


@admin.register(Snippet)
class SnippetAdmin(admin.ModelAdmin):
    list_display = ("business", "key", "title")
    search_fields = ("business__name", "key", "title", "content")
    list_filter = ("business",)


@admin.register(BusinessMember)
class BusinessMemberAdmin(admin.ModelAdmin):
    list_display = ("business", "user", "role", "created_at")
    list_filter = ("business", "role")
    search_fields = ("business__name", "user__username", "user__email")


@admin.register(Resource)
class ResourceAdmin(admin.ModelAdmin):
    list_display = ("business", "name", "capacity", "is_active", "updated_at")
    list_filter = ("business", "is_active")
    search_fields = ("business__name", "name")


@admin.register(OpeningRule)
class OpeningRuleAdmin(admin.ModelAdmin):
    list_display = ("business", "resource", "weekday", "start_time", "end_time", "slot_minutes")
    list_filter = ("business", "resource", "weekday")
    search_fields = ("business__name", "resource__name")


@admin.register(DayOverride)
class DayOverrideAdmin(admin.ModelAdmin):
    list_display = ("business", "resource", "date", "is_closed", "note")
    list_filter = ("business", "resource", "is_closed")
    search_fields = ("business__name", "resource__name", "note")


@admin.register(SlotOverride)
class SlotOverrideAdmin(admin.ModelAdmin):
    list_display = ("business", "resource", "date", "start_time", "end_time", "status", "capacity")
    list_filter = ("business", "resource", "status", "date")
    search_fields = ("business__name", "resource__name")


@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = ("business", "resource", "start", "end", "status", "fb_sender_id")
    list_filter = ("business", "resource", "status")
    search_fields = ("business__name", "resource__name", "fb_sender_id", "note")
    date_hierarchy = "start"
