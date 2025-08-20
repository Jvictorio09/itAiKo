# myApp/views.py
from __future__ import annotations

import hmac, hashlib, json, logging, time as _time, requests, re
from datetime import datetime, timedelta, time as dtime
from zoneinfo import ZoneInfo

from django.conf import settings
from django.http import HttpResponse, JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.cache import cache
from django.shortcuts import get_object_or_404, render, redirect
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django import forms
from django.middleware.csrf import get_token

from .models import Business, BusinessMember, Resource, Booking, Snippet  # ensure Snippet exists

# Availability helpers (your updated utils)
try:
    from .availability_utils import free_slots_for_day, is_range_free, nearest_free_slot
except Exception:
    free_slots_for_day = None
    is_range_free = None
    nearest_free_slot = None

from openai import OpenAI

log = logging.getLogger("messenger.webhook")

GRAPH_BASE = "https://graph.facebook.com/v20.0"
GRAPH_MSGS = f"{GRAPH_BASE}/me/messages"
OPENAI_API_KEY = getattr(settings, "OPENAI_API_KEY", "")
client = OpenAI(api_key=OPENAI_API_KEY)


# =========================================================
# Facebook helpers
# =========================================================

def _verify_sig(app_secret: str, body: bytes, header: str) -> bool:
    if not app_secret:
        log.warning("FB_APP_SECRET missing; skipping signature check.")
        return True
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(app_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header.split("=", 1)[1], expected)

def _send_graph(page_token: str, payload: dict, tries: int = 2):
    params = {"access_token": page_token}
    headers = {"Content-Type": "application/json"}
    for i in range(tries):
        try:
            r = requests.post(GRAPH_MSGS, params=params, json=payload, headers=headers, timeout=12)
            if r.status_code < 500:
                return r
            log.error("Graph %s: %s", r.status_code, r.text)
        except requests.RequestException as e:
            log.warning("Graph error: %s", e)
        _time.sleep(0.4 * (i + 1))
    return None

def _typing(page_token: str, rid: str, on=True):
    _send_graph(page_token, {
        "recipient": {"id": rid},
        "sender_action": "typing_on" if on else "typing_off"
    })

def _send_text(page_token: str, rid: str, text: str):
    _send_graph(page_token, {"recipient": {"id": rid}, "message": {"text": text[:2000]}})


# =========================================================
# Prompt / GPT reply
# =========================================================

_UNIVERSAL_PERSONA = (
    "You are a compassionate, friendly-but-professional Filipino customer assistant. "
    "Use natural Taglish (mix simple English + Filipino). Be concise, warm, and respectful. "
    "Avoid slang that could sound rude. Ask only one clear follow-up question if details are missing. "
    "Keep replies short and helpful."
)

def _compose_prompt(biz: Business) -> str:
    parts = [_UNIVERSAL_PERSONA]
    if getattr(biz, "system_prompt", ""):
        parts.append(biz.system_prompt.strip())
    if getattr(biz, "business_context", ""):
        parts += ["\n### Business Context", biz.business_context.strip()]
    # Optional snippets, if model exists
    if hasattr(biz, "snippets"):
        for sn in biz.snippets.all():
            label = (sn.title or sn.key or "Snippet").title()
            parts += [f"\n### {label}", (sn.content or "").strip()]
    # Guardrails / restricted topics
    if getattr(biz, "blocked_keywords", None):
        try:
            blocked = ", ".join(biz.blocked_keywords)  # ArrayField/list expected
        except Exception:
            blocked = str(biz.blocked_keywords)
        parts += [f"\n### Restricted\nNever discuss: {blocked}."]
    return "\n".join([p for p in parts if p])

def _ai_reply(biz: Business, user_msg: str) -> str:
    try:
        r = client.chat.completions.create(
            model=biz.model_name,
            temperature=float(biz.temperature),
            max_tokens=int(biz.max_tokens),
            messages=[
                {"role": "system", "content": _compose_prompt(biz)},
                {"role": "user", "content": user_msg},
            ],
        )
        return (r.choices[0].message.content or "").strip()
    except Exception:
        log.exception("OpenAI error")
        return "Sorry, nagka-issue sa system. Pakiulit po ang tanong."


# =========================================================
# Availability intent + parsing
# =========================================================

# Per-sender lightweight ctx (just signals we're in a booking flow)
def _ctx_key(biz: Business, sid: str) -> str:
    return f"mbot:ctx:{biz.slug}:{sid}:avail"

def _get_ctx(biz: Business, sid: str) -> dict:
    return cache.get(_ctx_key(biz, sid), {})

def _set_ctx(biz: Business, sid: str, ctx: dict | None = None, minutes: int = 30):
    cache.set(_ctx_key(biz, sid), (ctx or {"active": True}), minutes * 60)

def _clear_ctx(biz: Business, sid: str):
    cache.delete(_ctx_key(biz, sid))

def _has_ctx(biz: Business, sid: str) -> bool:
    return bool(cache.get(_ctx_key(biz, sid)))

def _tz(biz: Business):
    try:
        return ZoneInfo(biz.timezone) if biz.timezone else timezone.get_current_timezone()
    except Exception:
        return timezone.get_current_timezone()
    
# --- NEW: duration parsing ---
def _parse_duration_minutes(text: str) -> int | None:
    t = (text or "").lower()
    m = re.search(r'(\d{1,2})\s*(h|hr|hrs|hour|hours)\b', t)
    if m:
        return int(m.group(1)) * 60
    m = re.search(r'(\d{1,2})\s*(d|day|days)\b', t)
    if m:
        return int(m.group(1)) * 24 * 60
    if re.search(r'\bhalf[-\s]?day\b', t):
        return 12 * 60
    if re.search(r'\bovernight\b', t):
        return 12 * 60
    return None

# --- NEW: context utilities for last window ---
def _update_ctx(biz: Business, sid: str, **kwargs):
    ctx = _get_ctx(biz, sid)
    ctx.update(kwargs)
    _set_ctx(biz, sid, ctx)

def _get_last_start(biz: Business, sid: str):
    ctx = _get_ctx(biz, sid)
    iso = ctx.get("last_start")
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso)
    except Exception:
        return None


# recognizer for “now”
NOW_WORDS_RE = re.compile(r"\b(now( na)?|right now|ngayon( na)?)\b", re.I)

# Strict time regex (2pm, 14:00, 2:30 PM, 2-4pm, 2 to 4; ignores bare 18 in Aug 18)
_TIME_RE = re.compile(r"(?<!\d)(?P<h>\d{1,2})(?::(?P<m>\d{2}))?\s*(?P<ampm>am|pm)?(?!\d)", re.I)

def _to_24h(h: int, m: int, ampm: str):
    ampm = (ampm or "").lower()
    if ampm == "am":
        h = 0 if h == 12 else h
    elif ampm == "pm":
        h = 12 if h == 12 else h + 12
    return h, m

def _parse_times(text: str):
    t = re.sub(r"\bto\b", "-", text, flags=re.I)  # "2 to 4pm" -> "2-4pm"
    t = t.replace("–", "-").replace("—", "-")
    out = []
    for m in _TIME_RE.finditer(t):
        h = int(m.group("h"))
        mi = int(m.group("m") or 0)
        ampm = (m.group("ampm") or "").lower()
        has_colon = m.group("m") is not None
        has_ampm = bool(ampm)
        if not has_colon and not has_ampm:
            continue
        if not (0 <= h <= 23 and 0 <= mi <= 59):
            continue
        out.append((h, mi, ampm))
        if len(out) == 2:
            break
    return out

def _parse_date_only(text: str, biz) -> datetime.date | None:
    t = (text or "").lower()
    today = timezone.localdate()
    if "today" in t or "ngayon" in t:
        return today
    if "tomorrow" in t or "bukas" in t:
        return today + timedelta(days=1)

    # YYYY-MM-DD
    m = re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", text or "")
    if m:
        try:
            y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
            return datetime(y, mo, d).date()
        except ValueError:
            pass

    # Aug 21 (, 2025)
    m2 = re.search(r"\b([A-Za-z]{3,9})\s+(\d{1,2})(?:,\s*(\d{4}))?\b", text or "")
    if m2:
        try:
            mon = datetime.strptime(m2.group(1)[:3], "%b").month
            day = int(m2.group(2))
            year = int(m2.group(3)) if m2.group(3) else today.year
            return datetime(year, mon, day).date()
        except Exception:
            pass
    return None

def _round_up_15(dtobj: datetime):
    minutes = (15 - (dtobj.minute % 15)) % 15
    base = dtobj.replace(second=0, microsecond=0)
    return base if minutes == 0 else base + timedelta(minutes=minutes)

def _parse_when(text: str, biz):
    """
    Return:
      (date_only, None) if only date is found,
      (start_dt, end_dt) if a concrete range is found (aware),
      (None, None) if not enough info.
    """
    date = _parse_date_only(text, biz)
    times = _parse_times(text)

    if NOW_WORDS_RE.search(text or ""):
        tz = _tz(biz)
        now_local = timezone.now().astimezone(tz)
        start = _round_up_15(now_local)
        end   = start + timedelta(hours=1)
        return (start, end)

    if date and not times:
        return (date, None)

    if date and times:
        tz = _tz(biz)
        def _mk(d: datetime.date, hh: int, mm: int) -> datetime:
            naive = datetime.combine(d, dtime(hh, mm))
            return timezone.make_aware(naive, tz)
        if len(times) == 1:
            h, m, a = times[0]
            if a:
                h, m = _to_24h(h, m, a)
            if not (0 <= h <= 23 and 0 <= m <= 59):
                return (date, None)
            start = _mk(date, h, m)
            end = start + timedelta(hours=1)
            return (start, end)

        (h1, m1, a1), (h2, m2, a2) = times
        if not a1 and a2:
            a1 = a2
        if a1: h1, m1 = _to_24h(h1, m1, a1)
        if a2: h2, m2 = _to_24h(h2, m2, a2)
        if not (0 <= h1 <= 23 and 0 <= m1 <= 59 and 0 <= h2 <= 23 and 0 <= m2 <= 59):
            return (date, None)
        start = _mk(date, h1, m1)
        end   = _mk(date, h2, m2)
        if end <= start:
            end = start + timedelta(hours=1)
        return (start, end)

    return (None, None)





# =========================================================
# Availability reply
# =========================================================

def _availability_reply(biz: Business, text: str, sender_id: str | None = None) -> str | None:
    

    desired_minutes = _parse_duration_minutes(text) or 60
    date_only = _parse_date_only(text, biz)
    when = _parse_when(text, biz)  # (date, None) OR (start,end)

    # If the user only changed the duration, reuse last start if we have it
    last_start = _get_last_start(biz, sender_id or "anon")

    # 1) If we have a concrete window (start,end), adjust to desired duration and check
    if isinstance(when[0], datetime) and isinstance(when[1], datetime):
        start = when[0]
        end = start + timedelta(minutes=desired_minutes)

        free_names = []
        for r in biz.resources.filter(is_active=True):
            try:
                if is_range_free and is_range_free(biz, r, start, end):
                    free_names.append(r.name)
            except Exception:
                log.exception("is_range_free error for resource %s", r.id)

        # save last asked window to context
        _update_ctx(biz, sender_id or "anon",
                    active=True,
                    last_start=start.isoformat(),
                    last_duration=desired_minutes,
                    last_date=start.date().isoformat())

        if free_names:
            span = f"{start.strftime('%b %d %I:%M %p').lstrip('0')}–{end.strftime('%I:%M %p').lstrip('0')}"
            show = ", ".join(free_names[:3]) + (" (and more)" if len(free_names) > 3 else "")
            return f"Available sa {span}. Free: {show}. I-hold ko ba?"
        else:
            # propose earliest continuous alternative for the same duration
            tz = _tz(biz)
            best = None
            if nearest_free_slot:
                for r in biz.resources.filter(is_active=True):
                    nxt = nearest_free_slot(biz, r, start.date(), duration_minutes=desired_minutes, days_ahead=7)
                    if nxt and (not best or nxt['start'] < best['start']):
                        best = nxt
            if best:
                astart = datetime.fromisoformat(best["start"]).astimezone(tz)
                return f"Booked na ’yung continuous {desired_minutes//60}h window. Ok ba {astart.strftime('%b %d %I:%M %p').lstrip('0')}?"
            return "Mukhang occupied ang oras na ’yan. May iba ka bang oras?"

    # 2) DATE ONLY (maybe with duration)
    if date_only and when == (date_only, None):
        # If user previously gave an exact time, reuse it with new duration
        if last_start and last_start.date() == date_only and desired_minutes != 60:
            start = last_start
            end = start + timedelta(minutes=desired_minutes)
            free_names = []
            for r in biz.resources.filter(is_active=True):
                try:
                    if is_range_free and is_range_free(biz, r, start, end):
                        free_names.append(r.name)
                except Exception:
                    pass
            _update_ctx(biz, sender_id or "anon",
                        active=True,
                        last_start=start.isoformat(),
                        last_duration=desired_minutes,
                        last_date=start.date().isoformat())
            if free_names:
                span = f"{start.strftime('%b %d %I:%M %p').lstrip('0')}–{end.strftime('%I:%M %p').lstrip('0')}"
                show = ", ".join(free_names[:3])
                return f"Available sa {span}. Free: {show}. I-hold ko ba?"
            # else fall through to search per-day windows

        if not free_slots_for_day:
            _set_ctx(biz, sender_id or "anon")
            return "Live calendar check is offline ngayon. Puwede ko kayong tulungan manually—anong oras po?"

        tz = _tz(biz)
        resources = list(biz.resources.filter(is_active=True))
        any_open = False
        lines = []

        for r in resources:
            slots = free_slots_for_day(biz, r, date_only, duration_minutes=desired_minutes)
            if not slots:
                continue
            any_open = True
            human = []
            for s in slots[:4]:
                st = datetime.fromisoformat(s["start"]).astimezone(tz)
                en = datetime.fromisoformat(s["end"]).astimezone(tz)
                human.append(f"{st.strftime('%I:%M %p').lstrip('0')}–{en.strftime('%I:%M %p').lstrip('0')}")
            lines.append(f"• {r.name}: {', '.join(human)} …")

        _update_ctx(biz, sender_id or "anon", active=True, last_date=date_only.isoformat(), last_duration=desired_minutes)

        if any_open:
            pretty = f"{date_only:%b %d}"
            return f"Availability for {pretty} (continuous {desired_minutes//60}h):\n" + "\n".join(lines) + "\n\nMay preferred time ka ba?"
        else:
            # don’t say “fully booked” for the whole day; it’s just the requested duration that’s tight
            best = None
            if nearest_free_slot:
                for r in resources:
                    nxt = nearest_free_slot(biz, r, date_only, duration_minutes=desired_minutes, days_ahead=7)
                    if nxt and (not best or nxt['start'] < best['start']):
                        best = nxt
            if best:
                astart = datetime.fromisoformat(best["start"]).astimezone(tz)
                return f"Walang continuous {desired_minutes//60}h window on {date_only:%b %d}. Earliest: {astart.strftime('%b %d %I:%M %p').lstrip('0')}. Ok ba ito?"
            return f"For a continuous {desired_minutes//60}h today, wala tayong window. Gusto mo bang mag-suggest ako ng oras bukas?"

    # 3) No date/time parsed yet → ask a single crisp follow-up
    _set_ctx(biz, sender_id or "anon")
    return "For when po ang booking (date at oras)?"

# --- AI-first NLU & booking router (drop-in) ---------------------
import json as _json
from datetime import datetime as _dt, timedelta as _td
from django.utils import timezone as _tz

# 1) NLU: ask the model to return strict JSON (no keyword lists)
def _ai_understand(biz: Business, user_msg: str) -> dict:
    """
    Returns a dict like:
    {
      "intent": "availability|booking|greeting|smalltalk|faq|other",
      "date": "YYYY-MM-DD" | null,
      "start_time": "HH:MM" | null,   # 24h, local to biz
      "duration_minutes": int | null,
      "service_type": str | null,     # e.g. "car_rental", "haircut"
      "resource_name": str | null,
      "notes": str | null,
      "confidence": 0.0-1.0
    }
    """
    # Guard: if no OpenAI key, safely fallback to simple other
    if not OPENAI_API_KEY:
        return {"intent": "other", "date": None, "start_time": None, "duration_minutes": None,
                "service_type": None, "resource_name": None, "notes": None, "confidence": 0.0}

    system = (
        _compose_prompt(biz)
        + "\n\nYou are an NLU parser. Extract user intent and entities for booking/availability across any business type. "
          "Return ONLY a single JSON object. Do not include code fences or commentary."
    )

    # Prefer JSON mode if supported; otherwise we post-process
    try:
        r = client.chat.completions.create(
            model=biz.model_name,
            temperature=0.1,
            max_tokens=min(512, int(biz.max_tokens or 512)),
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system},
                {"role": "user",
                 "content": (
                    "Extract intent and fields.\n"
                    "Schema:\n"
                    "{"
                    "\"intent\": \"availability|booking|greeting|smalltalk|faq|other\","
                    "\"date\": \"YYYY-MM-DD|null\","
                    "\"start_time\": \"HH:MM|null\","
                    "\"duration_minutes\": \"int|null\","
                    "\"service_type\": \"string|null\","
                    "\"resource_name\": \"string|null\","
                    "\"notes\": \"string|null\","
                    "\"confidence\": \"0.0-1.0\""
                    "}\n\n"
                    f"User: {user_msg}"
                 )},
            ],
        )
        raw = (r.choices[0].message.content or "{}").strip()
        parsed = _json.loads(raw)
    except Exception:
        log.exception("NLU error; fallback to 'other'")
        parsed = {"intent": "other", "date": None, "start_time": None,
                  "duration_minutes": None, "service_type": None,
                  "resource_name": None, "notes": None, "confidence": 0.0}

    # Normalize types
    parsed.setdefault("intent", "other")
    parsed["date"] = parsed.get("date") or None
    parsed["start_time"] = parsed.get("start_time") or None
    try:
        dm = parsed.get("duration_minutes")
        parsed["duration_minutes"] = int(dm) if dm not in (None, "", "null") else None
    except Exception:
        parsed["duration_minutes"] = None
    parsed["service_type"] = (parsed.get("service_type") or None)
    parsed["resource_name"] = (parsed.get("resource_name") or None)
    parsed["notes"] = (parsed.get("notes") or None)
    try:
        parsed["confidence"] = float(parsed.get("confidence") or 0.0)
    except Exception:
        parsed["confidence"] = 0.0
    return parsed

# 2) Per-sender context (merge, don’t reset)
def _ctx_key(sender_id: str) -> str:
    return f"ctx:{sender_id}"

def _get_ctx(sender_id: str) -> dict:
    return cache.get(_ctx_key(sender_id), {})

def _set_ctx(sender_id: str, ctx: dict):
    cache.set(_ctx_key(sender_id), ctx, 3600)

def _clear_ctx(sender_id: str):
    cache.delete(_ctx_key(sender_id))

def _merge_ctx(ctx: dict, parsed: dict) -> dict:
    # Only overwrite fields user actually provided
    for k in ["date", "start_time", "duration_minutes", "service_type", "resource_name", "notes"]:
        v = parsed.get(k, None)
        if v not in (None, "", "null"):
            ctx[k] = v
    return ctx

# 3) Resolve fuzzy time like “today/later”
def _biz_tzinfo(biz: Business):
    from zoneinfo import ZoneInfo
    try:
        return ZoneInfo(biz.timezone) if biz.timezone else _tz.get_current_timezone()
    except Exception:
        return _tz.get_current_timezone()

def _round_up_15(dtobj):
    minutes = (15 - (dtobj.minute % 15)) % 15
    base = dtobj.replace(second=0, microsecond=0)
    return base if minutes == 0 else base + _td(minutes=minutes)

def _resolve_window(biz: Business, ctx: dict) -> tuple[datetime|None, datetime|None]:
    """
    Turn (date, start_time, duration_minutes) into aware start/end.
    If missing, fill reasonable defaults based on lead time.
    """
    tz = _biz_tzinfo(biz)
    now_local = _tz.now().astimezone(tz)
    cfg = getattr(biz, "availability_config", {}) or {}
    lead = int(cfg.get("lead_minutes", 0))

    # date
    date_str = ctx.get("date")
    if date_str in (None, "", "null"):
        # If the user said "later/today" the NLU should set date=today. If not, assume today.
        date_obj = _tz.localdate()
    else:
        try:
            date_obj = _dt.strptime(date_str, "%Y-%m-%d").date()
        except Exception:
            date_obj = _tz.localdate()

    # start_time
    st_str = ctx.get("start_time")
    if st_str:
        try:
            hh, mm = [int(x) for x in st_str.split(":")[:2]]
            start_naive = _dt.combine(date_obj, dtime(hh, mm))
        except Exception:
            start_naive = _dt.combine(date_obj, dtime(0, 0))
    else:
        # If none, choose the earliest valid start after lead time (rounded)
        min_start = now_local + _td(minutes=lead)
        if date_obj > _tz.localdate():
            start_naive = _dt.combine(date_obj, dtime(9, 0))  # reasonable default next-day
        else:
            start_naive = _round_up_15(min_start).replace(tzinfo=None)

    start = timezone.make_aware(start_naive, tz)

    # duration
    dur = int(ctx.get("duration_minutes") or 60)
    end = start + _td(minutes=dur)
    return start, end

# 4) Check all active resources; pick best option(s)
def _find_free_window_any_resource(biz: Business, start: datetime, end: datetime):
    # Return (resource, start, end) if any active resource is free
    for r in biz.resources.filter(is_active=True).order_by("name"):
        if is_range_free(biz, r, start, end):
            return r, start, end
    return None, None, None

def _suggest_alternatives(biz: Business, start: datetime, end: datetime, scans=6, step_minutes=30):
    # Try +/- steps after requested start
    alts = []
    forward = start
    for i in range(scans):
        forward = forward + _td(minutes=step_minutes)
        r, s, e = _find_free_window_any_resource(biz, forward, forward + (end - start))
        if r:
            alts.append((r, s, e))
            break
    backward = start
    for i in range(scans):
        backward = backward - _td(minutes=step_minutes)
        if backward.date() < _tz.localdate() - _td(days=1):
            break
        r, s, e = _find_free_window_any_resource(biz, backward, backward + (end - start))
        if r:
            alts.append((r, s, e))
            break
    return alts

# 5) Booking-mode brain
def _booking_router(biz: Business, sender_id: str, user_msg: str) -> str | None:
    """
    Returns a human message if we handled booking/availability,
    or None to let general AI handle smalltalk/faq/other.
    """
    parsed = _ai_understand(biz, user_msg)
    intent = parsed.get("intent", "other")

    # Only enter booking flow if the model thinks so
    if intent not in {"availability", "booking", "reservation"} and parsed.get("date") is None and parsed.get("start_time") is None:
        return None  # let GPT smalltalk/faq handle it

    # Merge with previous context
    ctx = _get_ctx(sender_id)
    ctx = _merge_ctx(ctx, parsed)

    # If key fields missing, ask one question at a time (business-agnostic)
    schema = getattr(biz, "booking_schema", None) or ["date", "start_time", "duration_minutes"]
    for f in schema:
        if ctx.get(f) in (None, "", "null"):
            prompt_map = {
                "date": "Kailan po ang booking ninyo? (hal. 2025-08-21 o 'bukas')",
                "start_time": "Anong oras po ang start? (hal. 20:00 o 8:00 PM)",
                "duration_minutes": "Gaano katagal po? (hal. 60, 180, 720/12 hours)"
            }
            _set_ctx(sender_id, ctx)
            return prompt_map.get(f, f"Could you provide {f}?")

    # We have enough to check availability
    start, end = _resolve_window(biz, ctx)

    # Validate across all active resources
    res, s, e = _find_free_window_any_resource(biz, start, end)
    if res:
        _clear_ctx(sender_id)  # we’re done (or you can keep to confirm later)
        s_local = s.astimezone(_biz_tzinfo(biz)).strftime("%b %d %I:%M %p")
        e_local = e.astimezone(_biz_tzinfo(biz)).strftime("%I:%M %p")
        return f"Available: {s_local} – {e_local}. Free: {res.name}. I-hold ko ba?"

    # No exact match → suggest alternatives (never say fully booked prematurely)
    alts = _suggest_alternatives(biz, start, end)
    if alts:
        lines = []
        for (r2, s2, e2) in alts[:2]:
            s2l = s2.astimezone(_biz_tzinfo(biz)).strftime("%b %d %I:%M %p")
            e2l = e2.astimezone(_biz_tzinfo(biz)).strftime("%I:%M %p")
            lines.append(f"• {s2l} – {e2l} ({r2.name})")
        _set_ctx(sender_id, ctx)  # keep context so user can pick
        return "Walang exact na tugma sa hiling ninyo, pero pwede ang:\n" + "\n".join(lines) + "\n\nPili po kayo?"

    _set_ctx(sender_id, ctx)
    return "Walang continuous window for that request. Gusto mo bang mag-suggest ako ng ibang oras o ibang araw?"
# --- end AI-first router -----------------------------------------


# =========================================================
# Webhook
# =========================================================
@csrf_exempt
def webhook(request, slug):
    """
    Messenger webhook endpoint.
    Handles incoming messages for a given business slug.
    """
    biz = get_object_or_404(Business, slug=slug)

    # Verification (GET)
    if request.method == "GET":
        token = request.GET.get("hub.verify_token")
        challenge = request.GET.get("hub.challenge") or ""
        return HttpResponse(
            challenge if token == biz.fb_verify_token else "Bad token",
            status=200 if token == biz.fb_verify_token else 403
        )

    # Messages (POST)
    if request.method == "POST":
        # Verify Meta signature (if set)
        if not _verify_sig(
            biz.fb_app_secret,
            request.body,
            request.headers.get("X-Hub-Signature-256", "")
        ):
            return HttpResponse("Invalid signature", status=403)

        try:
            payload = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError:
            return HttpResponse("Bad JSON", status=400)

        page_token = getattr(biz, "fb_page_access_token", "")
        for entry in payload.get("entry", []):
            for event in entry.get("messaging", []):
                msg = event.get("message", {}) or {}

                # Skip echoes (page/admin)
                if msg.get("is_echo"):
                    continue

                sender_id = event.get("sender", {}).get("id")
                if not sender_id:
                    continue

                text = (msg.get("text") or "").strip()
                if not text:
                    continue

                # Strip hashtag commands like "#manual hi"
                if text.startswith("#"):
                    parts = text.split(maxsplit=1)
                    text = parts[1].strip() if len(parts) > 1 else ""
                    if not text:
                        continue

                # If the page token isn't configured, fail gracefully
                if not page_token:
                    log.error("FB page token missing for biz %s", biz.slug)
                    continue

                _typing(page_token, sender_id, True)
                try:
                    # Availability-first: only handle if the helper thinks it's a booking ask
                    # (Ensure _availability_reply returns None for non-booking messages.)
                    avail_text = _availability_reply(biz, text, sender_id)
                    if avail_text is not None:
                        _send_text(page_token, sender_id, avail_text)
                    else:
                        # General AI reply (respects your prompt stack)
                        reply = _ai_reply(biz, text)
                        _send_text(page_token, sender_id, reply)
                except Exception:
                    log.exception("Error handling message")
                    _send_text(page_token, sender_id, "Oops, nagka-issue sandali. Pakiulit po.")
                finally:
                    _typing(page_token, sender_id, False)

        return HttpResponse("ok", status=200)

    return HttpResponse(status=405)


# =========================================================
# Portal (pages for humans)
# =========================================================

def _user_can_access(user, biz: Business) -> bool:
    return user.is_superuser or BusinessMember.objects.filter(user=user, business=biz).exists()

def _first_membership_slug(user):
    return (
        BusinessMember.objects
        .filter(user=user)
        .values_list("business__slug", flat=True)
        .first()
    )

def portal_home(request):
    if not request.user.is_authenticated:
        return redirect("portal_login")
    slug = _first_membership_slug(request.user)
    if slug:
        return redirect("portal_calendar", slug=slug)
    return render(request, "portal_select.html", {"memberships": []})

@require_http_methods(["GET", "POST"])
def portal_login(request):
    if request.method == "POST":
        user = authenticate(
            request,
            username=request.POST.get("username"),
            password=request.POST.get("password"),
        )
        if user:
            login(request, user)
            dest = request.GET.get("next")
            if not dest:
                slug = _first_membership_slug(user)
                dest = reverse("portal_calendar", kwargs={"slug": slug}) if slug else reverse("portal_home")
            return redirect(dest)
        return render(request, "portal_login.html", {"error": "Invalid credentials."})
    return render(request, "portal_login.html", {})

@login_required
def portal_logout(request):
    logout(request)
    return redirect("portal_login")

@login_required
def portal_dashboard(request, slug):
    biz = get_object_or_404(Business, slug=slug)
    if not _user_can_access(request.user, biz):
        return HttpResponseForbidden("No access")
    resources = biz.resources.filter(is_active=True)
    return render(
        request,
        "portal_dashboard.html",
        {"biz": biz, "resources": resources, "csrf": get_token(request)},
    )

@login_required
def portal_calendar(request, slug):
    biz = get_object_or_404(Business, slug=slug)
    if not _user_can_access(request.user, biz):
        return HttpResponseForbidden("No access")
    resources = biz.resources.filter(is_active=True).order_by("name")
    ctx = {
        "biz": biz,
        "resources": resources,
        "selected_date": timezone.localdate().isoformat(),
        "has_resources": resources.exists(),
        "csrf": get_token(request),
    }
    return render(request, "portal_calendar.html", ctx)


# =========================================================
# Simple Booking API (available/booked only)
# =========================================================

def _biz_auth(request, biz: Business) -> bool:
    """
    Simple machine-to-machine auth for the portal JS.
    Accept either ?token=... or X-Manage-Token header.
    If biz.manage_token is blank, allow in DEBUG for local dev.
    """
    token = request.headers.get("X-Manage-Token") or request.GET.get("token")
    if biz.manage_token:
        return token == biz.manage_token
    return settings.DEBUG  # allow while configuring

def _overlaps_qs(biz: Business, res: Resource, start, end):
    return Booking.objects.filter(
        business=biz, resource=res, status__in=["hold", "confirmed"],
        start__lt=end, end__gt=start
    )

@require_http_methods(["GET"])
def list_bookings(request, slug, resource_id):
    biz = get_object_or_404(Business, slug=slug)
    if not _biz_auth(request, biz):
        return HttpResponseForbidden("bad token")

    start = parse_datetime(request.GET.get("from") or "")
    end   = parse_datetime(request.GET.get("to") or "")
    if not (start and end):
        return HttpResponseBadRequest("from & to (ISO8601) required")
    if end <= start:
        return HttpResponseBadRequest("invalid range")

    res = get_object_or_404(Resource, pk=resource_id, business=biz)
    qs = _overlaps_qs(biz, res, start, end)
    data = [{
        "id": b.id,
        "title": "Booked" if b.status == "confirmed" else "On hold",
        "start": b.start.isoformat(),
        "end": b.end.isoformat(),
        "status": b.status,
    } for b in qs]
    return JsonResponse({"bookings": data})

@csrf_exempt
@require_http_methods(["POST"])
def create_booking(request, slug, resource_id):
    biz = get_object_or_404(Business, slug=slug)
    if not _biz_auth(request, biz):
        return HttpResponseForbidden("bad token")

    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        return HttpResponseBadRequest("invalid json")

    start = parse_datetime(body.get("start") or "")
    end   = parse_datetime(body.get("end") or "")
    status = body.get("status") or "confirmed"
    note   = body.get("note") or ""

    if not (start and end):
        return HttpResponseBadRequest("start & end (ISO8601) required")
    if end <= start:
        return HttpResponseBadRequest("end must be after start")

    res = get_object_or_404(Resource, pk=resource_id, business=biz)

    # Capacity check
    if _overlaps_qs(biz, res, start, end).count() >= max(1, res.capacity):
        return JsonResponse({"ok": False, "reason": "conflict"}, status=409)

    b = Booking.objects.create(
        business=biz, resource=res, start=start, end=end,
        status=status, note=note
    )
    return JsonResponse({"ok": True, "id": b.id}, status=201)

@csrf_exempt
@require_http_methods(["DELETE"])
def delete_booking(request, slug, resource_id):
    biz = get_object_or_404(Business, slug=slug)
    if not _biz_auth(request, biz):
        return HttpResponseForbidden("bad token")

    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        return HttpResponseBadRequest("invalid json")

    bid = body.get("id")
    if not bid:
        return HttpResponseBadRequest("id required")

    res = get_object_or_404(Resource, pk=resource_id, business=biz)
    get_object_or_404(Booking, pk=bid, business=biz, resource=res).delete()
    return JsonResponse({"ok": True})


# ============================
# Resource management (portal)
# ============================

class ResourceForm(forms.ModelForm):
    class Meta:
        model = Resource
        fields = ["name", "capacity", "is_active"]
        widgets = {
            "name": forms.TextInput(attrs={"class": "w-full border border-gray-300 rounded-xl px-3 py-2", "placeholder": "e.g., Mitsubishi Mirage"}),
            "capacity": forms.NumberInput(attrs={"class": "w-full border border-gray-300 rounded-xl px-3 py-2", "min": 1}),
            "is_active": forms.CheckboxInput(attrs={"class": "h-4 w-4"}),
        }

@login_required
def portal_resources(request, slug):
    biz = get_object_or_404(Business, slug=slug)
    if not _user_can_access(request.user, biz):
        return HttpResponseForbidden("No access")

    resources = biz.resources.order_by("-is_active", "name")
    form = ResourceForm()
    return render(request, "portal_resources.html", {"biz": biz, "resources": resources, "form": form})

@login_required
@require_http_methods(["POST"])
def resource_create(request, slug):
    biz = get_object_or_404(Business, slug=slug)
    if not _user_can_access(request.user, biz):
        return HttpResponseForbidden("No access")

    form = ResourceForm(request.POST)
    if form.is_valid():
        r = form.save(commit=False)
        r.business = biz
        if r.capacity is None or r.capacity < 1:
            r.capacity = 1
        r.save()
        messages.success(request, "Resource created.")
    else:
        messages.error(request, "Please fix the errors below.")
        resources = biz.resources.order_by("-is_active", "name")
        return render(request, "portal_resources.html", {"biz": biz, "resources": resources, "form": form})

    return redirect("portal_resources", slug=biz.slug)

@login_required
@require_http_methods(["POST"])
def resource_update(request, slug, resource_id):
    biz = get_object_or_404(Business, slug=slug)
    if not _user_can_access(request.user, biz):
        return HttpResponseForbidden("No access")

    res = get_object_or_404(Resource, pk=resource_id, business=biz)
    form = ResourceForm(request.POST, instance=res)
    if form.is_valid():
        obj = form.save(commit=False)
        if obj.capacity is None or obj.capacity < 1:
            obj.capacity = 1
        obj.save()
        messages.success(request, "Resource updated.")
    else:
        messages.error(request, "Please fix the errors.")
    return redirect("portal_resources", slug=biz.slug)

@login_required
@require_http_methods(["POST"])
def resource_delete(request, slug, resource_id):
    biz = get_object_or_404(Business, slug=slug)
    if not _user_can_access(request.user, biz):
        return HttpResponseForbidden("No access")

    res = get_object_or_404(Resource, pk=resource_id, business=biz)
    res.delete()
    messages.success(request, "Resource deleted.")
    return redirect("portal_resources", slug=biz.slug)


# ============================
# Session-auth Resource JSON API
# ============================

@login_required
@require_http_methods(["GET", "POST"])
def portal_api_resources(request, slug):
    biz = get_object_or_404(Business, slug=slug)
    if not _user_can_access(request.user, biz):
        return HttpResponseForbidden("No access")

    if request.method == "GET":
        data = [
            {"id": r.id, "name": r.name, "capacity": r.capacity, "is_active": r.is_active}
            for r in biz.resources.order_by("name")
        ]
        return JsonResponse({"resources": data})

    # POST create
    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        return HttpResponseBadRequest("invalid json")

    name = (body.get("name") or "").strip()
    capacity = int(body.get("capacity") or 1)
    is_active = bool(body.get("is_active"))
    if not name:
        return HttpResponseBadRequest("name required")
    if capacity < 1:
        capacity = 1

    r = Resource.objects.create(business=biz, name=name, capacity=capacity, is_active=is_active)
    return JsonResponse({"id": r.id, "name": r.name, "capacity": r.capacity, "is_active": r.is_active}, status=201)

@login_required
@require_http_methods(["PUT", "PATCH", "DELETE"])
def portal_api_resource_detail(request, slug, resource_id):
    biz = get_object_or_404(Business, slug=slug)
    if not _user_can_access(request.user, biz):
        return HttpResponseForbidden("No access")

    r = get_object_or_404(Resource, pk=resource_id, business=biz)

    if request.method in ["PUT", "PATCH"]:
        try:
            body = json.loads(request.body.decode("utf-8") or "{}")
        except Exception:
            return HttpResponseBadRequest("invalid json")

        name = (body.get("name") or r.name).strip()
        capacity = int(body.get("capacity") or r.capacity)
        is_active = body.get("is_active")
        if capacity < 1:
            capacity = 1

        r.name = name
        r.capacity = capacity
        if is_active is not None:
            r.is_active = bool(is_active)
        r.save()
        return JsonResponse({"id": r.id, "name": r.name, "capacity": r.capacity, "is_active": r.is_active})

    # DELETE
    r.delete()
    return JsonResponse({"ok": True})


# =========================================================
# Public pages
# =========================================================

def legal_privacy(request):
    return render(request, "legal/privacy.html", {"updated": timezone.now().date()})

def legal_terms(request):
    return render(request, "legal/terms.html", {"updated": timezone.now().date()})

def legal_data_deletion(request):
    return render(request, "legal/data_deletion.html", {"updated": timezone.now().date()})

def about(request):
    return render(request, "about.html", {})

def contact(request):
    return render(request, "contact.html", {})
