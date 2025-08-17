from datetime import datetime, timedelta
from django.utils import timezone
from myApp.models import OpeningRule, DayOverride, SlotOverride, Booking, Resource, Business

def _aware(dt):
    if timezone.is_naive(dt):
        return timezone.make_aware(dt, timezone.get_current_timezone())
    return dt

def _combine(date, t):
    return _aware(datetime.combine(date, t))

def build_slots(biz: Business, resource: Resource, date):
    """
    Return a list of available slots for a given date:
    [{"start": aware_dt, "end": aware_dt, "capacity": int}, ...]
    Applies: DayOverride, SlotOverride, and existing Booking capacity usage.
    """
    # Day closed?
    if DayOverride.objects.filter(business=biz, resource=resource, date=date, is_closed=True).exists():
        return []

    # Generate base slots from weekly OpeningRules
    slots = []
    rules = OpeningRule.objects.filter(business=biz, resource=resource, weekday=date.weekday())
    for r in rules:
        cursor = _combine(date, r.start_time)
        end_of_rule = _combine(date, r.end_time)
        step = timedelta(minutes=r.slot_minutes)
        while cursor + step <= end_of_rule:
            slots.append({"start": cursor, "end": cursor + step, "capacity": resource.capacity})
            cursor += step

    # Apply per-day SlotOverrides (add or block)
    for ov in SlotOverride.objects.filter(business=biz, resource=resource, date=date):
        ov_start = _combine(date, ov.start_time)
        ov_end   = _combine(date, ov.end_time)
        if ov.status == "unavailable":
            slots = [s for s in slots if not (s["start"] >= ov_start and s["end"] <= ov_end)]
        else:  # available
            slots.append({"start": ov_start, "end": ov_end, "capacity": ov.capacity})

    # Drop past slots
    now = timezone.now()
    slots = [s for s in slots if s["end"] > now]

    # Subtract capacity for overlapping bookings (hold+confirmed)
    day_start = _aware(datetime.combine(date, datetime.min.time()))
    day_end   = _aware(datetime.combine(date, datetime.max.time()))
    bookings = Booking.objects.filter(
        business=biz, resource=resource, status__in=["hold","confirmed"],
        start__lt=day_end, end__gt=day_start
    )

    for b in bookings:
        for s in slots:
            if not (b.end <= s["start"] or b.start >= s["end"]):
                s["capacity"] -= 1

    # Keep only positive-capacity slots; sort by time
    slots = [s for s in slots if s["capacity"] > 0]
    slots.sort(key=lambda x: x["start"])
    return slots
