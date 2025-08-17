from __future__ import annotations
from datetime import datetime, timedelta, time as dtime
from zoneinfo import ZoneInfo

from django.utils import timezone
from django.db.models import Q

from myApp.models import Booking, DayOverride, SlotOverride, OpeningRule, Resource, Business  # adjust path if needed


# ---- timezone helpers ----
def _biz_tz(biz: Business):
    try:
        return ZoneInfo(biz.timezone) if biz.timezone else timezone.get_current_timezone()
    except Exception:
        return timezone.get_current_timezone()

def _aware(biz: Business, dt: datetime) -> datetime:
    """Make naive dt aware in business timezone."""
    if timezone.is_aware(dt):
        return dt
    return timezone.make_aware(dt, _biz_tz(biz))


# ---- small utils ----
def _overlaps(qs, start: datetime, end: datetime):
    """Return queryset of records overlapping [start, end)."""
    return qs.filter(start__lt=end, end__gt=start)

def _day_is_closed(biz: Business, res: Resource, date):
    return DayOverride.objects.filter(business=biz, resource=res, date=date, is_closed=True).exists()


# ---- public: is a concrete window free? ----
def is_range_free(biz: Business, res: Resource, start: datetime, end: datetime) -> bool:
    start = _aware(biz, start)
    end   = _aware(biz, end)
    if end <= start:
        return False

    # closed day?
    if _day_is_closed(biz, res, start.date()):
        return False

    # blocked by SlotOverride (unavailable)?
    if SlotOverride.objects.filter(
        business=biz, resource=res, status="unavailable",
        date=start.date(),
        start_time__lt=end.timetz(), end_time__gt=start.timetz()
    ).exists():
        return False

    # capacity check via active bookings (hold/confirmed)
    overlaps = _overlaps(
        Booking.objects.filter(
            business=biz, resource=res, status__in=["hold", "confirmed"]
        ),
        start, end
    ).count()

    return overlaps < max(1, res.capacity)


# ---- public: list free starts for a day (simple, 60m default) ----
def free_slots_for_day(
    biz: Business, res: Resource, date, duration_minutes: int = 60
):
    """
    Returns a list of dicts: [{"start": ISO, "end": ISO}, ...] for the given date.
    Uses OpeningRule as base; if none, defaults to 08:00–20:00, step = duration.
    Honors DayOverride (closed) and SlotOverride 'unavailable'.
    Capacity is checked against existing bookings.
    """
    if _day_is_closed(biz, res, date):
        return []

    tz = _biz_tz(biz)

    rules = list(OpeningRule.objects.filter(business=biz, resource=res, weekday=date.weekday()))
    if not rules:
        rules = [type("TmpRule", (), {
            "start_time": dtime(8, 0), "end_time": dtime(20, 0), "slot_minutes": duration_minutes
        })()]

    slots = []
    step = max(15, duration_minutes)  # don’t spam too fine
    for rule in rules:
        st = datetime.combine(date, rule.start_time)
        end_rule = datetime.combine(date, rule.end_time)
        cursor = st
        while cursor + timedelta(minutes=duration_minutes) <= end_rule:
            s = _aware(biz, cursor)
            e = s + timedelta(minutes=duration_minutes)
            # blocked by unavailable override?
            if SlotOverride.objects.filter(
                business=biz, resource=res, status="unavailable",
                date=date, start_time__lt=e.timetz(), end_time__gt=s.timetz()
            ).exists():
                cursor += timedelta(minutes=step)
                continue
            # capacity free?
            if is_range_free(biz, res, s, e):
                slots.append({"start": s.astimezone(tz).isoformat(), "end": e.astimezone(tz).isoformat()})
            cursor += timedelta(minutes=step)

    return slots
