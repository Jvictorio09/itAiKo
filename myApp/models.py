# messenger_bot/models.py
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator

# ---- Calendar/availability provider choices (extensible) ----
AVAILABILITY_PROVIDERS = [
    ("internal_calendar", "Internal Calendar"),   # this file (day toggles + slots)
    ("google_calendar", "Google Calendar"),       # future: adapter-based expansion
]


class Business(models.Model):
    name = models.CharField(max_length=120)
    slug = models.SlugField(unique=True)

    # Messenger creds (keep as-is; used by your bot)
    fb_page_access_token = models.TextField(help_text="Page Access Token")
    fb_verify_token = models.CharField(max_length=255, help_text="Webhook verify token (Meta will call this)")
    fb_app_secret = models.CharField(max_length=255, help_text="For X-Hub-Signature-256 validation")

    # AI config (keep as-is)
    model_name = models.CharField(max_length=64, default="gpt-4o-mini")
    temperature = models.FloatField(default=0.4, validators=[MinValueValidator(0.0), MaxValueValidator(2.0)])
    max_tokens = models.PositiveIntegerField(default=300)

    # Prompt stack (keep as-is)
    system_prompt = models.TextField(help_text="Brand voice / core instructions")
    business_context = models.TextField(blank=True, help_text="Hours, contacts, etc")

    # UX / guardrails (keep as-is)
    quick_replies = models.JSONField(default=list, blank=True)
    blocked_keywords = models.JSONField(default=list, blank=True)

    # Meta (keep as-is)
    timezone = models.CharField(max_length=64, default="Asia/Manila")

    # NEW: lightweight management/auth + provider selection
    manage_token = models.CharField(
        max_length=64, blank=True, default="",
        help_text="Optional shared secret for simple API management endpoints"
    )
    availability_provider = models.CharField(
        max_length=40, choices=AVAILABILITY_PROVIDERS,
        default="internal_calendar",
        help_text="Which availability backend to use for this business"
    )
    availability_config = models.JSONField(
        default=dict, blank=True,
        help_text="Provider-specific config (e.g. calendar IDs, API creds)"
    )

    booking_schema = models.JSONField(
    default=list, blank=True,
    help_text="List of required fields: e.g. ['date', 'time', 'service_type', 'stylist']"
    )


    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    ai_enabled = models.BooleanField(default=True, help_text="Turn AI router on/off for this business")

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name
    

from django.conf import settings

class BusinessMember(models.Model):
    ROLE = [("owner", "Owner"), ("manager", "Manager"), ("viewer", "Viewer")]
    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name="members")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="business_memberships")
    role = models.CharField(max_length=10, choices=ROLE, default="manager")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("business", "user")
        ordering = ["business", "user_id"]

    def __str__(self):
        return f"{self.user} @ {self.business.slug} ({self.role})"


class Snippet(models.Model):
    """Reusable content chunks per business: rates, location, policies, FAQs…"""
    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name="snippets")
    key = models.SlugField(help_text="e.g., rates, location, reservation_policy")
    title = models.CharField(max_length=120, blank=True)
    content = models.TextField()

    class Meta:
        unique_together = ("business", "key")
        ordering = ["key"]

    def __str__(self):
        return f"{self.business.slug}:{self.key}"


# -------------------------
# Internal Calendar models
# -------------------------

class Resource(models.Model):
    """
    Anything bookable (generic):
    - For car rental: 'Mitsubishi Mirage' (capacity=1 or number of identical units)
    - For salon: a chair or stylist
    - For clinic: a room/doctor
    """
    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name="resources")
    name = models.CharField(max_length=80)
    capacity = models.PositiveIntegerField(default=1, help_text="How many parallel bookings per slot")
    is_active = models.BooleanField(default=True)
    external_resource_id = models.CharField(max_length=120, blank=True, help_text="Optional mapping to external calendar")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["business", "name"]

    def __str__(self):
        return f"{self.business.slug}:{self.name}"


class OpeningRule(models.Model):
    """
    Weekly template that generates slots for a weekday.
    Example: Monday 09:00–19:00, slot_minutes=60 → 10 one-hour slots.
    """
    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name="opening_rules")
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, related_name="opening_rules")
    weekday = models.IntegerField(choices=[(i, i) for i in range(7)], help_text="0=Mon … 6=Sun")
    start_time = models.TimeField()
    end_time = models.TimeField()
    slot_minutes = models.PositiveIntegerField(default=60)

    class Meta:
        ordering = ["resource", "weekday", "start_time"]

    def __str__(self):
        return f"{self.resource} W{self.weekday} {self.start_time}-{self.end_time} ({self.slot_minutes}m)"


class DayOverride(models.Model):
    """
    Close or open a specific date (holiday, maintenance, fully booked).
    If is_closed=True, no slots for that date unless SlotOverride adds some.
    """
    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name="day_overrides")
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, related_name="day_overrides")
    date = models.DateField()
    is_closed = models.BooleanField(default=True)
    note = models.CharField(max_length=200, blank=True)

    class Meta:
        unique_together = ("resource", "date")
        ordering = ["-date"]

    def __str__(self):
        state = "closed" if self.is_closed else "open"
        return f"{self.resource} {self.date} [{state}]"


class SlotOverride(models.Model):
    """
    Ad-hoc slot added or blocked on a specific date/time.
    Use status='unavailable' to block; 'available' to add extra slots.
    """
    STATUS = [("available", "available"), ("unavailable", "unavailable")]

    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name="slot_overrides")
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, related_name="slot_overrides")
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    capacity = models.PositiveIntegerField(default=1)
    status = models.CharField(max_length=12, choices=STATUS, default="available")

    class Meta:
        ordering = ["-date", "start_time"]

    def __str__(self):
        return f"{self.resource} {self.date} {self.start_time}-{self.end_time} ({self.status})"


class Booking(models.Model):
    """
    Actual reservations (or holds) that consume capacity.
    Keep it generic so any business type can use it.
    """
    STATUS = [("hold", "Hold"), ("confirmed", "Confirmed"), ("cancelled", "Cancelled")]

    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name="bookings")
    resource = models.ForeignKey(Resource, on_delete=models.PROTECT, related_name="bookings")
    start = models.DateTimeField()
    end = models.DateTimeField()
    status = models.CharField(max_length=10, choices=STATUS, default="hold")
    fb_sender_id = models.CharField(max_length=64, blank=True, help_text="Optional: Messenger user id for follow-up")
    note = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["business", "resource", "start", "end", "status"]),
        ]
        ordering = ["-start"]

    def __str__(self):
        return f"{self.resource} {self.start:%Y-%m-%d %H:%M} → {self.end:%H:%M} ({self.status})"
