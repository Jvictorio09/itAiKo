# myApp/views.py
from __future__ import annotations

import hmac, hashlib, json, logging, time, requests, re
from datetime import datetime, timedelta, time as dtime
from zoneinfo import ZoneInfo

from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.http import (
    HttpResponse, JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
)
from django.middleware.csrf import get_token
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import Business, BusinessMember, Resource, Booking, Snippet  # Snippet used in prompt

# Availability helpers (internal calendar)
try:
    from .availability_utils import free_slots_for_day, is_range_free
except Exception:
    free_slots_for_day = None
    is_range_free = None

# ---- OpenAI client (only if you configured OPENAI_API_KEY) ----
try:
    from openai import OpenAI
    _OPENAI_API_KEY = getattr(settings, "OPENAI_API_KEY", "")
    _openai_client = OpenAI(api_key=_OPENAI_API_KEY) if _OPENAI_API_KEY else None
except Exception:
    _openai_client = None

log = logging.getLogger("myApp.webhook")

# ---------------------------
# Facebook Graph helpers
# ---------------------------
GRAPH_BASE = "https://graph.facebook.com/v20.0"
GRAPH_MSGS = f"{GRAPH_BASE}/me/messages"

def _fb_verify_sig(app_secret: str, body: bytes, header: str) -> bool:
    if not app_secret:
        log.warning("FB_APP_SECRET missing; skipping signature check.")
        return True
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(app_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header.split("=", 1)[1], expected)

def _fb_send(page_token: str, payload: dict, tries: int = 2):
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
    _fb_send(page_token, {
        "recipient": {"id": rid},
        "sender_action": "typing_on" if on else "typing_off"
    })

def _send_text(page_token: str, rid: str, text: str):
    _fb_send(page_token, {"recipient": {"id": rid}, "message": {"text": text[:2000]}})

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
    # include snippets (rates, FAQs, policies, etc.)
    for sn in biz.snippets.all():
        label = (sn.title or sn.key).title()
        parts += [f"\n### {label}", (sn.content or "").strip()]
    if biz.blocked_keywords:
        parts += [f"\n### Restricted\nNever discuss: {', '.join(biz.blocked_keywords)}."]
    return "\n".join([p for p in parts if p])

def _ai_reply(biz: Business, user_msg: str) -> str:
    # If OpenAI isn’t configured, return an apologetic fallback
    if not _openai_client:
        return "Hi! I’m online pero walang AI credits configured. Pakimesage ulit po later. 🙏"
    try:
        r = _openai_client.chat.completions.create(
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
# Availability: context + parsing + reply
# ---------------------------

# Context keys (per-sender, short-lived)
def _avail_ctx_key(biz: Business, sid: str) -> str:
    return f"mbot:ctx:{biz.slug}:{sid}:avail"

def _has_avail_ctx(biz: Business, sid: str) -> bool:
    return bool(cache.get(_avail_ctx_key(biz, sid)))

def _set_avail_ctx(biz: Business, sid: str, minutes: int = 15):
    cache.set(_avail_ctx_key(biz, sid), True, minutes * 60)

def _clear_avail_ctx(biz: Business, sid: str):
    cache.delete(_avail_ctx_key(biz, sid))

# timezone
def _tz(biz: Business):
    try:
        return ZoneInfo(biz.timezone) if biz.timezone else timezone.get_current_timezone()
    except Exception:
        return timezone.get_current_timezone()

# recognizer for "now"
NOW_WORDS_RE = re.compile(r"\b(now( na)?|right now|ngayon( na)?)\b", re.I)

# Strict time regex: supports 2pm, 14:00, 2:30 PM, 2-4pm, 2 to 4 — ignores “18” inside “Aug 18”
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

def _parse_date_only(text: str, biz: Business):
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

    # Mon 21 or August 21 (, 2025)
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

def _parse_when(text: str, biz: Business):
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

        def _mk(d, hh, mm):
            naive = datetime.combine(d, dtime(hh, mm))
            return timezone.make_aware(naive, tz)

        if len(times) == 1:
            h, m, ampm = times[0]
            if ampm:
                h, m = _to_24h(h, m, ampm)
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

# Intent gate: soft, context-aware
def _wants_availability(biz: Business, text: str, sender_id: str | None = None) -> bool:
    t = (text or "").lower()
    if NOW_WORDS_RE.search(t):
        return True
    # Strong hints — minimal keyword use to prevent false positives on chit-chat
    kw = ["available", "availability", "avail", "book", "booking", "reserve", "slot", "schedule",
          "pwede", "kaya", "bakante", "open", "free"]
    if any(k in t for k in kw):
        return True
    if sender_id and _has_avail_ctx(biz, sender_id):
        return True
    try:
        if _parse_date_only(text, biz) or _parse_times(text):
            return True
    except Exception:
        pass
    return False

# Friendly follow-ups per field
def _field_prompt(field):
    prompts = {
        "date": "Kailan po ang booking ninyo? (hal. Aug 21 o bukas)",
        "time": "Anong oras po ang gusto ninyo?",
        "destination": "Saan po ang pupuntahan?",
        "service_type": "Anong service po ang kailangan (hal. haircut, manicure, car rental)?",
        "stylist": "May preferred stylist po ba?",
        "guests": "Ilang tao po ang kasama?",
    }
    return prompts.get(field, f"Could you share your {field}?")

# Super-light slot-filling for non-date fields (kept simple & safe)
def _parse_booking_info(text: str, schema: list[str]) -> dict:
    info, lower = {}, (text or "").lower()

    if "date" in schema:
        if "bukas" in lower:
            info["date"] = (timezone.localdate() + timedelta(days=1)).isoformat()
        elif re.search(r"\b([A-Za-z]{3,9})\s+\d{1,2}(?:,\s*\d{4})?\b", text or "") or re.search(r"\b\d{4}-\d{2}-\d{2}\b", text or ""):
            d = _parse_date_only(text, None)  # timezone not needed for just date
            if d:
                info["date"] = d.isoformat()

    if "time" in schema:
        times = _parse_times(text or "")
        if times:
            h, m, ampm = times[0]
            if ampm: h, m = _to_24h(h, m, ampm)
            info["time"] = f"{h:02d}:{m:02d}"

    if "destination" in schema:
        for w in ["tagaytay", "qc", "quezon city", "makati", "antipolo"]:
            if w in lower:
                info["destination"] = w
                break

    if "service_type" in schema:
        for w in ["haircut", "manicure", "rent", "rental", "catering", "event"]:
            if w in lower:
                info["service_type"] = w
                break

    return info

def _nearest_alt_slot(biz: Business, date, minutes: int = 60):
    if not free_slots_for_day:
        return None
    res = biz.resources.filter(is_active=True).first()
    if not res:
        return None
    for d_offset in range(0, 4):
        d = date + timedelta(days=d_offset)
        slots = free_slots_for_day(biz, res, d, duration_minutes=minutes)
        if slots:
            return slots[0]
    return None

def _availability_reply(biz: Business, user_text: str, sender_id: str | None = None) -> str | None:
    """
    Friendly, context-aware availability reply.
    Returns a short Taglish response, or None if not availability-related.
    """
    if not _wants_availability(biz, user_text, sender_id):
        return None

    cfg = biz.availability_config or {}
    followups = cfg.get("availability_followups") or [
        "For when po ang booking (date & time)?",
    ]

    # Parse date/time
    date = _parse_date_only(user_text, biz)
    times = _parse_times(user_text)

    # 0) Nothing usable → ask follow-ups, set short-lived context
    if not date and not times:
        _set_avail_ctx(biz, sender_id or "anon")
        if len(followups) == 1:
            return followups[0]
        return "Para ma-check ko agad, paki-share po: " + " • ".join(followups[:2])

    # 1) Time only → ask for the date specifically (don’t guess today)
    if not date and times:
        _set_avail_ctx(biz, sender_id or "anon")
        (h, m, ampm) = times[0]
        if ampm:
            h, m = _to_24h(h, m, ampm)
        hh = (h % 12) or 12
        ap = "AM" if h < 12 else "PM"
        return f"Noted: {hh}:{m:02d} {ap}. Anong date po?"

    # 2) Date only → list first few free times per active resource
    if date and not times:
        tz = _tz(biz)
        resources = list(biz.resources.filter(is_active=True))
        lines = []

        for r in resources:
            if not free_slots_for_day:
                continue
            slots = free_slots_for_day(biz, r, date, duration_minutes=60)
            if not slots:
                continue
            human = []
            for s in slots[:4]:
                st = datetime.fromisoformat(s["start"]).astimezone(tz)
                human.append(st.strftime("%I:%M %p").lstrip("0"))
            lines.append(f"• {r.name}: {', '.join(human)} …")

        _set_avail_ctx(biz, sender_id or "anon")  # keep context until they pick a time

        if lines:
            return f"Availability for {date:%b %d}:\n" + "\n".join(lines) + "\n\nMay preferred time ka ba?"
        else:
            return f"Mukhang fully booked tayo sa {date:%b %d}. Gusto mo bang i-check ko ang next available day?"

    # 3) Date + time(s) → check concrete window (default 1h if single time)
    start_end = _parse_when(user_text, biz)
    if start_end and isinstance(start_end[0], datetime) and isinstance(start_end[1], datetime):
        start, end = start_end
        ok_list = []
        for r in biz.resources.filter(is_active=True):
            if is_range_free and is_range_free(biz, r, start, end):
                ok_list.append(r.name)

        if sender_id:
            _clear_avail_ctx(biz, sender_id)

        if ok_list:
            span = f"{start.strftime('%b %d %I:%M %p').lstrip('0')}–{end.strftime('%I:%M %p').lstrip('0')}"
            tops = ", ".join(ok_list[:3])
            more = " (and more)" if len(ok_list) > 3 else ""
            return f"Available sa {span}. Free: {tops}{more}. I-hold ko ba?"
        else:
            alt = _nearest_alt_slot(biz, start.date(), minutes=60)
            if alt:
                astart = datetime.fromisoformat(alt["start"]).astimezone(_tz(biz))
                return f"Booked na ’yung oras na ’yan. Ok po ba {astart.strftime('%b %d %I:%M %p').lstrip('0')}?"
            return "Mukhang occupied ang oras na ’yan. May iba ka bang oras?"

    # Fallback (shouldn’t hit)
    _set_avail_ctx(biz, sender_id or "anon")
    return "For when po ang booking (date & time)?"

# ---------------------------
# Webhook (single-app setup)
# ---------------------------

@csrf_exempt
def webhook(request, slug):
    biz = get_object_or_404(Business, slug=slug)

    if request.method == "GET":
        token = request.GET.get("hub.verify_token")
        challenge = request.GET.get("hub.challenge") or ""
        return HttpResponse(challenge if token == biz.fb_verify_token else "Bad token",
                            status=200 if token == biz.fb_verify_token else 403)

    if request.method == "POST":
        # Verify Meta signature (if configured)
        if not _fb_verify_sig(
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

                # skip page echos
                if msg.get("is_echo"):
                    continue

                user_psid = event.get("sender", {}).get("id")
                if not user_psid:
                    continue

                text = (msg.get("text") or "").strip()
                if not text:
                    continue

                # allow manual commands like "#hello" without triggering bot
                if text.startswith("#"):
                    parts = text.split(maxsplit=1)
                    text = parts[1] if len(parts) > 1 else ""
                    if not text:
                        continue

                _typing(biz.fb_page_access_token, user_psid, True)

                # 1) Availability-first (but only if it actually looks like it)
                avail_text = _availability_reply(biz, text, user_psid)
                if avail_text is not None:
                    _send_text(biz.fb_page_access_token, user_psid, avail_text)
                    _typing(biz.fb_page_access_token, user_psid, False)
                    continue

                # 2) Otherwise general AI, honoring system_prompt + business_context
                reply = _ai_reply(biz, text)
                _send_text(biz.fb_page_access_token, user_psid, reply)
                _typing(biz.fb_page_access_token, user_psid, False)

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
    return render(request, "portal_dashboard.html", {"biz": biz, "resources": resources, "csrf": get_token(request)})

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

def _overlaps_qs(biz: Business, res: Resource, start, end):
    return Booking.objects.filter(
        business=biz, resource=res, status__in=["hold", "confirmed"],
        start__lt=end, end__gt=start
    )

@require_http_methods(["GET"])
def list_bookings(request, slug, resource_id):
    biz = get_object_or_404(Business, slug=slug)
    # lightweight machine-to-machine auth if you want: ?token=...
    token_header = request.headers.get("X-Manage-Token") or request.GET.get("token")
    if biz.manage_token and token_header != biz.manage_token:
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
    token_header = request.headers.get("X-Manage-Token") or request.GET.get("token")
    if biz.manage_token and token_header != biz.manage_token:
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
    token_header = request.headers.get("X-Manage-Token") or request.GET.get("token")
    if biz.manage_token and token_header != biz.manage_token:
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
# JSON: resources (for your SPA/table)
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

    # POST create JSON
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

# ---------------------------
# Public pages
# ---------------------------

from django.utils.timezone import now as _now

def legal_privacy(request):
    return render(request, "legal/privacy.html", {"updated": _now().date()})

def legal_terms(request):
    return render(request, "legal/terms.html", {"updated": _now().date()})

def legal_data_deletion(request):
    return render(request, "legal/data_deletion.html", {"updated": _now().date()})

def about(request):
    return render(request, "about.html", {})

def contact(request):
    return render(request, "contact.html", {})
