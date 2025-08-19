# myApp/availability_utils.py
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Optional, Iterable, Tuple
from datetime import datetime, timedelta, date as ddate, time as dtime
from zoneinfo import ZoneInfo

from django.utils import timezone
from django.db.models import Q

from myApp.models import (
    Booking, DayOverride, SlotOverride, OpeningRule, Resource, Business
)

# =========================================================
# Timezone helpers
# =========================================================

def _biz_tz(biz: Business):
    try:
        return ZoneInfo(biz.timezone) if biz.timezone else timezone.get_current_timezone()
    except Exception:
        return timezone.get_current_timezone()

def _aware(biz: Business, dt: datetime) -> datetime:
    """Make naive dt timezone-aware in the business timezone."""
    if timezone.is_aware(dt):
        return dt
    return timezone.make_aware(dt, _biz_tz(biz))

def _local_now(biz: Business) -> datetime:
    return timezone.now().astimezone(_biz_tz(biz))

# =========================================================
# Small utils
# =========================================================

def _overlaps(qs, start: datetime, end: datetime):
    """Records overlapping [start, end)."""
    return qs.filter(start__lt=end, end__gt=start)

def _day_is_closed(biz: Business, res: Resource, on_date: ddate) -> bool:
    """True if an explicit DayOverride says closed."""
    return DayOverride.objects.filter(
        business=biz, resource=res, date=on_date, is_closed=True
    ).exists()

def _slot_overrides_for(biz: Business, res: Resource, on_date: ddate) -> List[SlotOverride]:
    return list(SlotOverride.objects.filter(business=biz, resource=res, date=on_date))

def _opening_rules_for(biz: Business, res: Resource, on_date: ddate) -> List[OpeningRule]:
    return list(OpeningRule.objects.filter(business=biz, resource=res, weekday=on_date.weekday()))

# =========================================================
# Capacity math (handles 'available' overrides that add capacity)
# =========================================================

def _extra_capacity_from_overrides(
    overrides: Iterable[SlotOverride], start: datetime, end: datetime
) -> int:
    """Sum of capacities from 'available' overrides that overlap the window."""
    total = 0
    for o in overrides:
        if o.status != "available":
            continue
        # Build aware datetimes for override window using the same date
        o_s = datetime.combine(o.date, o.start_time, tzinfo=start.tzinfo)
        o_e = datetime.combine(o.date, o.end_time, tzinfo=start.tzinfo)
        if o_s < end and o_e > start:
            total += max(0, int(o.capacity or 0))
    return total

def _blocked_by_unavailable(overrides: Iterable[SlotOverride], start: datetime, end: datetime) -> bool:
    """True if any 'unavailable' override intersects the window."""
    for o in overrides:
        if o.status != "unavailable":
            continue
        o_s = datetime.combine(o.date, o.start_time, tzinfo=start.tzinfo)
        o_e = datetime.combine(o.date, o.end_time, tzinfo=start.tzinfo)
        if o_s < end and o_e > start:
            return True
    return False

# =========================================================
# Public: check if a concrete window is free
# =========================================================

def is_range_free(biz: Business, res: Resource, start: datetime, end: datetime) -> bool:
    """
    True if [start, end) is free:
      - Day not explicitly closed
      - Not blocked by 'unavailable' SlotOverride
      - Bookings below capacity (resource capacity + any 'available' overrides)
    """
    start = _aware(biz, start)
    end   = _aware(biz, end)
    if end <= start:
        return False

    # Day closed?
    if _day_is_closed(biz, res, start.date()):
        return False

    # Overrides on the day
    overrides = _slot_overrides_for(biz, res, start.date())

    # Hard block by 'unavailable'?
    if _blocked_by_unavailable(overrides, start, end):
        return False

    # Capacity = base + extra capacity contributed by 'available' overrides
    base_capacity = max(1, int(res.capacity or 1))
    extra_capacity = _extra_capacity_from_overrides(overrides, start, end)
    allowed_capacity = base_capacity + extra_capacity

    # Count overlapping holds/confirmed
    overlaps = _overlaps(
        Booking.objects.filter(
            business=biz, resource=res, status__in=["hold", "confirmed"]
        ),
        start, end
    ).count()

    return overlaps < allowed_capacity

# =========================================================
# Public: list free starts for a day
# =========================================================

def free_slots_for_day(
    biz: Business,
    res: Resource,
    on_date: ddate,
    duration_minutes: int = 60,
) -> List[Dict[str, str]]:
    """
    Returns a list: [{"start": ISO, "end": ISO}, ...] of FREE slots for `on_date`.

    Logic:
      - If DayOverride.is_closed=True → []
      - Base availability comes from OpeningRule windows (step = max(15, rule.slot_minutes))
      - 'unavailable' SlotOverride blocks windows it overlaps
      - 'available' SlotOverride ADDS capacity/time. We generate slots inside these windows too
      - Past/too-soon slots are filtered out based on availability_config (lead time)
      - Capacity is enforced via is_range_free()

    Biz.availability_config (optional):
      - lead_minutes: int minimum minutes from now before a slot can start (default 0)
      - day_cutoff_hour: int(0-23) don't offer slots earlier than this hour on the same day (optional)
    """
    tz = _biz_tz(biz)
    now_local = _local_now(biz)

    # Config knobs
    cfg = getattr(biz, "availability_config", {}) or {}
    lead_minutes = int(cfg.get("lead_minutes", 0))
    min_start = now_local + timedelta(minutes=lead_minutes)

    # Hard close?
    if _day_is_closed(biz, res, on_date):
        return []

    rules = _opening_rules_for(biz, res, on_date)

    # If no rules, we can still honor 'available' overrides (ad-hoc open windows)
    if not rules:
        rules = []  # empty means we will rely solely on 'available' overrides below

    overrides = _slot_overrides_for(biz, res, on_date)
    unavailable_overrides = [o for o in overrides if o.status == "unavailable"]
    available_overrides   = [o for o in overrides if o.status == "available"]

    results: List[Tuple[datetime, datetime]] = []

    # --- 1) Generate from OpeningRules ---
    for rule in rules:
        # Base window from the rule
        window_start = datetime.combine(on_date, rule.start_time)
        window_end   = datetime.combine(on_date, rule.end_time)
        window_start = _aware(biz, window_start)
        window_end   = _aware(biz, window_end)

        step = max(15, int(getattr(rule, "slot_minutes", duration_minutes) or duration_minutes))
        cursor = window_start
        while cursor + timedelta(minutes=duration_minutes) <= window_end:
            s = cursor
            e = s + timedelta(minutes=duration_minutes)

            # Skip past / too soon
            if s < min_start:
                cursor += timedelta(minutes=step)
                continue

            # Blocked by an 'unavailable' override?
            if _blocked_by_unavailable(unavailable_overrides, s, e):
                cursor += timedelta(minutes=step)
                continue

            if is_range_free(biz, res, s, e):
                results.append((s, e))

            cursor += timedelta(minutes=step)

    # --- 2) Generate from 'available' SlotOverrides (they can extend/open outside rules) ---
    for o in available_overrides:
        o_s = _aware(biz, datetime.combine(on_date, o.start_time))
        o_e = _aware(biz, datetime.combine(on_date, o.end_time))
        # Use step = max(15, duration)
        step = max(15, duration_minutes)
        cursor = o_s
        while cursor + timedelta(minutes=duration_minutes) <= o_e:
            s = cursor
            e = s + timedelta(minutes=duration_minutes)

            if s < min_start:
                cursor += timedelta(minutes=step)
                continue

            # Even inside an available override, we must ensure not blocked by any 'unavailable'
            if _blocked_by_unavailable(unavailable_overrides, s, e):
                cursor += timedelta(minutes=step)
                continue

            if is_range_free(biz, res, s, e):
                results.append((s, e))

            cursor += timedelta(minutes=step)

    # Deduplicate & sort
    seen = set()
    uniq: List[Tuple[datetime, datetime]] = []
    for s, e in results:
        key = (s.isoformat(), e.isoformat())
        if key not in seen:
            seen.add(key)
            uniq.append((s, e))

    uniq.sort(key=lambda x: x[0])

    # Return as ISO in business tz
    out: List[Dict[str, str]] = []
    for s, e in uniq:
        out.append({
            "start": s.astimezone(tz).isoformat(),
            "end":   e.astimezone(tz).isoformat(),
        })
    return out

# =========================================================
# Optional helper: find the next free slot from a given date
# =========================================================

def nearest_free_slot(
    biz: Business,
    res: Resource,
    start_date: ddate,
    duration_minutes: int = 60,
    days_ahead: int = 7
) -> Optional[Dict[str, str]]:
    """
    Scan from start_date up to days_ahead for the first free slot.
    """
    for i in range(days_ahead + 1):
        d = start_date + timedelta(days=i)
        slots = free_slots_for_day(biz, res, d, duration_minutes=duration_minutes)
        if slots:
            return slots[0]
    return None
