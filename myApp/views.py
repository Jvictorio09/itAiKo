# messenger_bot/views.py
import hmac, hashlib, json, logging, time, requests, re
from datetime import datetime, timedelta, time as dtime

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.conf import settings

from .models import Business, Resource

# Availability helpers (from your earlier file)
try:
    from myApp.availability_utils import free_slots_for_day, is_range_free
except Exception:
    # If not available, keep None; we'll gracefully fall back to GPT.
    free_slots_for_day = None
    is_range_free = None

from openai import OpenAI

log = logging.getLogger("messenger.webhook")

GRAPH_BASE = "https://graph.facebook.com/v20.0"
GRAPH_MSGS = f"{GRAPH_BASE}/me/messages"
OPENAI_API_KEY = getattr(settings, "OPENAI_API_KEY", "")

client = OpenAI(api_key=OPENAI_API_KEY)

# ---------------------------
# Facebook helpers
# ---------------------------

def _verify_sig(app_secret: str, body: bytes, header: str) -> bool:
    if not app_secret:
        log.warning("FB_APP_SECRET missing for this tenant; skipping signature check.")
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
        time.sleep(0.4 * (i + 1))
    return None

def _typing(page_token: str, rid: str, on=True):
    _send_graph(page_token, {
        "recipient": {"id": rid},
        "sender_action": "typing_on" if on else "typing_off"
    })

def _send_text(page_token: str, rid: str, text: str):
    _send_graph(page_token, {"recipient": {"id": rid}, "message": {"text": text[:2000]}})

def _mute_key(slug: str, sid: str) -> str:
    return f"mbot:mute:{slug}:{sid}"

def _is_muted(slug: str, sid: str) -> bool:
    return bool(cache.get(_mute_key(slug, sid)))

def _mute(slug: str, sid: str, minutes: int):
    cache.set(_mute_key(slug, sid), True, minutes * 60)

# ---------------------------
# Prompt / GPT reply
# ---------------------------

_UNIVERSAL_PERSONA = (
    "You are a compassionate, friendly-but-professional Filipino customer assistant. "
    "Use natural Taglish (mix simple English + Filipino). Be concise, warm, and respectful. "
    "Avoid slang that could sound rude. Ask only one clear follow-up question if details are missing. "
    "Keep replies short and helpful."
)

def _compose_prompt(biz: Business) -> str:
    parts = [_UNIVERSAL_PERSONA]
    if biz.system_prompt:
        parts.append(biz.system_prompt.strip())
    if biz.business_context:
        parts += ["\n### Business Context", biz.business_context.strip()]
    for sn in biz.snippets.all():
        label = (sn.title or sn.key).title()
        parts += [f"\n### {label}", sn.content.strip()]
    if biz.blocked_keywords:
        parts += [f"\n### Restricted\nNever discuss: {', '.join(biz.blocked_keywords)}."]
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

# ---------------------------
# Availability intent + parsing
# ---------------------------

# --- lightweight availability context (per sender) ---
def _avail_ctx_key(biz: Business, sid: str) -> str:
    return f"mbot:ctx:{biz.slug}:{sid}:avail"




import re

def _wants_availability(biz: Business, text: str, sender_id: str | None = None) -> bool:
    t = (text or "").lower()

    if NOW_WORDS_RE.search(t):
        return True
    # strong keywords
    kw = ["available", "availability", "avail", "book", "booking", "reserve", "slot", "schedule",
          "pwede", "kaya", "bakante", "open", "free"]
    if any(k in t for k in kw):
        return True

    # if we recently asked them for date/time, treat their reply as availability even if short
    if sender_id and _has_avail_ctx(biz, sender_id):
        return True

    # heuristic: if message contains a parseable date or time, consider it availability-ish
    from datetime import datetime as _dt
    # reuse your strict _parse_times / _parse_date_only
    try:
        if _parse_date_only(text, biz) or _parse_times(text):
            return True
    except Exception:
        pass

    return False


def _tz(biz: Business):
    from zoneinfo import ZoneInfo
    try:
        return ZoneInfo(biz.timezone) if biz.timezone else timezone.get_current_timezone()
    except Exception:
        return timezone.get_current_timezone()


# ------ Strict, defensive time/date parsing (no naming clashes) ------

import re
import datetime as dt
from zoneinfo import ZoneInfo
from django.utils import timezone

# Strict time regex:
# - won’t match digits inside bigger numbers (e.g., 2025)
# - supports: 2pm, 14:00, 2:30 PM, 2-4pm, 2 to 4
_TIME_RE = re.compile(
    r"(?<!\d)(?P<h>\d{1,2})(?::(?P<m>\d{2}))?\s*(?P<ampm>am|pm)?(?!\d)",
    re.I
)
# If other code references TIME_RE, keep this alias:
TIME_RE = _TIME_RE


def _to_24h(h: int, m: int, ampm: str):
    """Convert 12h to 24h if am/pm is present."""
    ampm = (ampm or "").lower()
    if ampm == "am":
        h = 0 if h == 12 else h
    elif ampm == "pm":
        h = 12 if h == 12 else h + 12
    return h, m


def _parse_times(text: str):
    """
    Return up to two VALID times from text as (hour, minute, ampm).
    IMPORTANT: ignores bare integers (e.g., '18' in 'Aug 18') unless
    they include a colon or am/pm. This prevents day numbers being
    misread as times.
    """
    t = re.sub(r"\bto\b", "-", text, flags=re.I)  # "2 to 4pm" -> "2-4pm"
    t = t.replace("–", "-").replace("—", "-")

    out = []
    for m in _TIME_RE.finditer(t):
        h = int(m.group("h"))
        mi = int(m.group("m") or 0)
        ampm = (m.group("ampm") or "").lower()

        # NEW: require either a colon or am/pm; otherwise skip (e.g., '18' in 'Aug 18')
        has_colon = m.group("m") is not None
        has_ampm = bool(ampm)
        if not has_colon and not has_ampm:
            continue

        # sanity check ranges
        if not (0 <= h <= 23 and 0 <= mi <= 59):
            continue

        out.append((h, mi, ampm))
        if len(out) == 2:
            break
    return out


def _tz(biz):
    """Business timezone as ZoneInfo; safe fallback."""
    try:
        return ZoneInfo(getattr(biz, "timezone", "") or str(timezone.get_current_timezone()))
    except Exception:
        return timezone.get_current_timezone()


def _parse_date_only(text: str, biz) -> dt.date | None:
    """Very light date parsing: today/ngayon, tomorrow/bukas, YYYY-MM-DD, 'Aug 21(, 2025)'."""
    t = text.lower()
    today = timezone.localdate()

    if "today" in t or "ngayon" in t:
        return today
    if "tomorrow" in t or "bukas" in t:
        return today + dt.timedelta(days=1)

    # YYYY-MM-DD
    m = re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", text)
    if m:
        try:
            y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
            return dt.date(y, mo, d)
        except ValueError:
            pass

    # Mon 21 or August 21 (, 2025)
    m2 = re.search(r"\b([A-Za-z]{3,9})\s+(\d{1,2})(?:,\s*(\d{4}))?\b", text)
    if m2:
        try:
            mon = dt.datetime.strptime(m2.group(1)[:3], "%b").month
            day = int(m2.group(2))
            year = int(m2.group(3)) if m2.group(3) else today.year
            return dt.date(year, mon, day)
        except Exception:
            pass

    return None


def _parse_when(text: str, biz):
    """
    Try to parse a date and optional time range from text.
    Returns:
      (date_only, None) if only date is found,
      (start_dt, end_dt) if a concrete range is found (aware datetimes),
      (None, None) if we can’t parse enough to proceed.
    """
    date = _parse_date_only(text, biz)
    times = _parse_times(text)

    if NOW_WORDS_RE.search(text or ""):
        tz = _tz(biz)
        now_local = timezone.now().astimezone(tz)
        start = _round_up_15(now_local)       # e.g., 1:47 → 2:00
        end   = start + timedelta(hours=1)    # default 1h window
        return (start, end)

    if date and not times:
        # date only -> let caller list slots
        return (date, None)

    if date and times:
        tz = _tz(biz)  # ZoneInfo

        def _mk(d: dt.date, hh: int, mm: int) -> dt.datetime:
            # build aware datetime safely
            naive = dt.datetime.combine(d, dt.time(hh, mm))
            return timezone.make_aware(naive, tz)

        # Single time → assume 1 hour window
        if len(times) == 1:
            h, m, ampm = times[0]
            if ampm:
                h, m = _to_24h(h, m, ampm)
            # re-validate after am/pm conversion
            if not (0 <= h <= 23 and 0 <= m <= 59):
                return (date, None)  # fallback to date-only
            start = _mk(date, h, m)
            end = start + dt.timedelta(hours=1)
            return (start, end)

        # Two times → build a range (inherit am/pm if only on the second: "2-4pm")
        (h1, m1, a1), (h2, m2, a2) = times
        if not a1 and a2:
            a1 = a2
        if a1:
            h1, m1 = _to_24h(h1, m1, a1)
        if a2:
            h2, m2 = _to_24h(h2, m2, a2)

        # final sanity after conversion
        if not (0 <= h1 <= 23 and 0 <= m1 <= 59 and 0 <= h2 <= 23 and 0 <= m2 <= 59):
            return (date, None)  # fallback to date-only

        start = _mk(date, h1, m1)
        end   = _mk(date, h2, m2)
        if end <= start:
            end = start + dt.timedelta(hours=1)
        return (start, end)

    # not enough info
    return (None, None)



# ---------------------------
# Availability response
# ---------------------------

# recognizer for "now"
NOW_WORDS_RE = re.compile(r"\b(now( na)?|right now|ngayon( na)?)\b", re.I)

def _round_up_15(dtobj):
    """Round up to the next 15-minute mark, keep seconds=0."""
    minutes = (15 - (dtobj.minute % 15)) % 15
    base = dtobj.replace(second=0, microsecond=0)
    return base if minutes == 0 else base + timedelta(minutes=minutes)

from django.core.cache import cache

def _field_prompt(field):
    prompts = {
        "date": "Kailan po ang booking ninyo? (hal. Aug 21 o bukas)",
        "time": "Anong oras po ang gusto ninyo?",
        "destination": "Saan po ang pupuntahan?",
        "service_type": "Anong service po ang kailangan (e.g., haircut, manicure, car rental)?",
        "stylist": "May preferred stylist po ba?",
        "guests": "Ilang tao po ang kasama?",
    }
    return prompts.get(field, f"Could you provide {field}?")


import re
from datetime import datetime

def _parse_booking_info(text, schema):
    info = {}
    lower = text.lower()

    if "date" in schema:
        if "bukas" in lower:
            info["date"] = (datetime.today() + timedelta(days=1)).date().isoformat()
        elif re.search(r"\baug(?:ust)?\s?\d{1,2}\b", lower):
            info["date"] = re.search(r"(aug(?:ust)?\s?\d{1,2})", lower).group(1)

    if "time" in schema:
        if "umaga" in lower:
            info["time"] = "09:00"
        elif "hapon" in lower:
            info["time"] = "15:00"
        elif match := re.search(r"(\d{1,2}(:\d{2})?\s?(am|pm))", lower):
            info["time"] = match.group(1)

    if "destination" in schema and any(w in lower for w in ["tagaytay", "qc", "makati"]):
        info["destination"] = [w for w in ["tagaytay","qc","makati"] if w in lower][0]

    if "service_type" in schema and any(w in lower for w in ["haircut","rent","catering","event"]):
        info["service_type"] = [w for w in ["haircut","rent","catering","event"] if w in lower][0]

    return info

def _check_internal_availability(biz, ctx):
    # Example: fetch slots from OpeningRule for ctx["date"] and ctx["time"]
    slots = []
    # TODO: implement properly
    return slots


def _ctx_key(sender_id):
    return f"ctx:{sender_id}"

def get_context(sender_id):
    return cache.get(_ctx_key(sender_id), {})

def set_context(sender_id, ctx):
    cache.set(_ctx_key(sender_id), ctx, timeout=3600)  # 1 hr

def clear_context(sender_id):
    cache.delete(_ctx_key(sender_id))

from .availability_utils import free_slots_for_day, is_range_free
import datetime as dt

def _availability_reply(biz, sender_id, user_msg):
    """
    Slot-filling AI for availability requests.
    """
    ctx = get_context(sender_id)
    schema = biz.booking_schema or ["date", "time"]  # fallback for legacy businesses

    # Step 1: Try to parse new info from user message
    parsed = _parse_booking_info(user_msg, schema)
    ctx.update(parsed)

    # Step 2: Check which fields are missing
    missing = [f for f in schema if f not in ctx]

    if missing:
        # Ask for the next missing slot
        next_field = missing[0]
        prompt = _field_prompt(next_field)
        set_context(sender_id, ctx)
        return prompt

    # Step 3: All fields filled → check availability
    clear_context(sender_id)

    # For car rental/salon/etc: plug into your Resource + OpeningRule
    available = _check_internal_availability(biz, ctx)

    if available:
        slots = "\n".join(f"• {s}" for s in available[:5])
        return f"Availability for {ctx['date']}:\n{slots}\n\nWould you like me to book this for you?"
    else:
        return "Sorry, fully booked for that slot. Want me to suggest another time?"



def _nearest_alt_slot(biz: Business, date: dt.date, minutes: int = 60):
    res = biz.resources.filter(is_active=True).first()
    if not res:
        return None
    # today + next 3 days scan
    for d_offset in range(0, 4):
        d = date + dt.timedelta(days=d_offset)
        slots = free_slots_for_day(biz, res, d, duration_minutes=minutes)
        if slots:
            return slots[0]
    return None

# ---------------------------
# Webhook
# ---------------------------


# views.py (webhook only – no mute at all)

from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
import json

@csrf_exempt
def webhook(request, slug):
    biz = get_object_or_404(Business, slug=slug)

    # --- Verification (GET) ---
    if request.method == "GET":
        token = request.GET.get("hub.verify_token")
        challenge = request.GET.get("hub.challenge") or ""
        return HttpResponse(
            challenge if token == biz.fb_verify_token else "Bad token",
            status=200 if token == biz.fb_verify_token else 403
        )

    # --- Messages (POST) ---
    if request.method == "POST":
        # Verify Meta signature
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

        for entry in payload.get("entry", []):
            for event in entry.get("messaging", []):
                msg = event.get("message", {}) or {}

                # If this is an echo (Page/admin message), do nothing.
                # We do NOT mute the thread anymore.
                if msg.get("is_echo"):
                    continue

                # User PSID
                user_psid = event.get("sender", {}).get("id")
                if not user_psid:
                    continue

                # Only handle text messages
                text = (msg.get("text") or "").strip()
                if not text:
                    continue

                # If someone types a hashtag "command", just strip it and continue.
                # (Prevents the bot from replying to things like "#manual hello")
                if text.startswith("#"):
                    parts = text.split(maxsplit=1)
                    text = parts[1] if len(parts) > 1 else ""
                    if not text:
                        continue

                # Availability-first path
                _typing(biz.fb_page_access_token, user_psid, True)
                avail_text = _availability_reply(biz, text, user_psid)  # pass PSID for follow-up context
                if avail_text is not None:
                    _send_text(biz.fb_page_access_token, user_psid, avail_text)
                    _typing(biz.fb_page_access_token, user_psid, False)
                    continue  # don't fall back to GPT

                # Default AI reply
                reply = _ai_reply(biz, text)
                _send_text(biz.fb_page_access_token, user_psid, reply)
                _typing(biz.fb_page_access_token, user_psid, False)

        return HttpResponse("ok", status=200)

    return HttpResponse(status=405)



    return HttpResponse(status=405)
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods
from django.http import (
    JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
)
from django.middleware.csrf import get_token
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.conf import settings
from django import forms
from django.contrib import messages


# ---- your models ----
from myApp.models import (
    Business, BusinessMember, Resource, Booking
)

# =========================================================
# Helpers
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

# =========================================================
# Portal (pages for humans)
# =========================================================

def portal_home(request):
    """Root → login or first business calendar."""
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


from django.middleware.csrf import get_token
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
        "csrf": get_token(request),  # ensures csrftoken cookie is set
    }
    return render(request, "portal_calendar.html", ctx)

# =========================================================
# Simple Booking API (available/booked only)
# =========================================================

@require_http_methods(["GET"])
def list_bookings(request, slug, resource_id):
    """
    GET /api/<slug>/resources/<id>/bookings?from=ISO&to=ISO&token=...
    Returns JSON: {"bookings":[{id,title,start,end,status},...]}
    """
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

from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
@require_http_methods(["POST"])
def create_booking(request, slug, resource_id):
    """
    POST /api/<slug>/resources/<id>/booking
    Body: {"start": ISO, "end": ISO, "status": "confirmed"|"hold", "note": "..."}
    """
    import json
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

    # Capacity check (no overlapping bookings beyond capacity)
    if _overlaps_qs(biz, res, start, end).count() >= res.capacity:
        return JsonResponse({"ok": False, "reason": "conflict"}, status=409)

    b = Booking.objects.create(
        business=biz, resource=res, start=start, end=end,
        status=status, note=note
    )
    return JsonResponse({"ok": True, "id": b.id}, status=201)

@csrf_exempt
@require_http_methods(["DELETE"])
def delete_booking(request, slug, resource_id):
    """
    DELETE /api/<slug>/resources/<id>/booking/delete
    Body: {"id": <booking_id>}
    """
    import json
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
    """Resources list + create form."""
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
        # Re-render the page with errors
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
    """
    Delete a resource. If you want to forbid delete when bookings exist,
    add a guard here to check Booking.objects.filter(resource=...).exists()
    """
    biz = get_object_or_404(Business, slug=slug)
    if not _user_can_access(request.user, biz):
        return HttpResponseForbidden("No access")

    res = get_object_or_404(Resource, pk=resource_id, business=biz)
    res.delete()
    messages.success(request, "Resource deleted.")
    return redirect("portal_resources", slug=biz.slug)


from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.forms.models import model_to_dict
import json

# ... keep your existing imports and helpers (_user_can_access) ...

@login_required
@require_http_methods(["GET", "POST"])
def portal_api_resources(request, slug):
    """Session-auth: list (GET) and create (POST) resources for a business."""
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

    r = Resource.objects.create(
        business=biz, name=name, capacity=capacity, is_active=is_active
    )
    return JsonResponse(
        {"id": r.id, "name": r.name, "capacity": r.capacity, "is_active": r.is_active},
        status=201
    )

@login_required
@require_http_methods(["PUT", "PATCH", "DELETE"])
def portal_api_resource_detail(request, slug, resource_id):
    """Session-auth: update or delete a single resource."""
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
        if capacity < 1: capacity = 1

        r.name = name
        r.capacity = capacity
        if is_active is not None:
            r.is_active = bool(is_active)
        r.save()
        return JsonResponse(
            {"id": r.id, "name": r.name, "capacity": r.capacity, "is_active": r.is_active}
        )

    # DELETE
    # Optional: block delete if bookings exist for this resource
    # if Booking.objects.filter(resource=r).exists(): return HttpResponseBadRequest("has bookings")
    r.delete()
    return JsonResponse({"ok": True})



# myApp/views_public.py
from django.shortcuts import render
from django.utils.timezone import now

def legal_privacy(request):
    return render(request, "legal/privacy.html", {"updated": now().date()})

def legal_terms(request):
    return render(request, "legal/terms.html", {"updated": now().date()})

def legal_data_deletion(request):
    return render(request, "legal/data_deletion.html", {"updated": now().date()})

def about(request):
    return render(request, "about.html", {})

def contact(request):
    return render(request, "contact.html", {})
