# ===========================
# Helpers (clean version)
# ===========================

import hmac, hashlib, json, logging, time, requests
from datetime import timedelta
from typing import Literal, Tuple

from django.http import HttpResponse
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings

from .models import Business

# Availability helpers (imported; we fall back gracefully if missing)
try:
    from myApp.availability_utils import free_slots_for_day, is_range_free  # noqa: F401
except Exception:
    free_slots_for_day = None
    is_range_free = None

from openai import OpenAI
log = logging.getLogger("messenger.webhook")

GRAPH_BASE = "https://graph.facebook.com/v20.0"
GRAPH_MSGS = f"{GRAPH_BASE}/me/messages"
OPENAI_API_KEY = getattr(settings, "OPENAI_API_KEY", "")
client = OpenAI(api_key=OPENAI_API_KEY)

# ---------------------------
# Facebook / Graph helpers
# ---------------------------

def _verify_sig(app_secret: str, body: bytes, header: str) -> bool:
    """Validate Meta X-Hub-Signature-256 header (if app_secret is set)."""
    if not app_secret:
        log.warning("FB_APP_SECRET missing; skipping signature check.")
        return True
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(app_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header.split("=", 1)[1], expected)

def _send_graph(page_token: str, payload: dict, tries: int = 2):
    """POST to Graph API with small retry on 5xx/connection errors."""
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

def _typing(page_token: str, rid: str, on: bool = True):
    """Toggle typing indicator."""
    _send_graph(page_token, {
        "recipient": {"id": rid},
        "sender_action": "typing_on" if on else "typing_off"
    })

def _send_text(page_token: str, rid: str, text: str):
    """Send plain text message (hard limit to be safe)."""
    _send_graph(page_token, {"recipient": {"id": rid}, "message": {"text": text[:2000]}})

# ---------------------------
# Prompt / GPT reply helpers
# ---------------------------

_UNIVERSAL_PERSONA = (
    "You are a compassionate, friendly-but-professional Filipino customer assistant. "
    "Use natural Taglish (mix simple English + Filipino). Be concise, warm, and respectful. "
    "Avoid slang that could sound rude. Ask only one clear follow-up question if details are missing. "
    "Keep replies short and helpful."
)

def _compose_prompt(biz: Business) -> str:
    """Build the system prompt from persona + system_prompt + context + snippets + restrictions."""
    parts = [_UNIVERSAL_PERSONA]

    if biz.system_prompt:
        parts.append(biz.system_prompt.strip())

    if biz.business_context:
        parts += ["\n### Business Context", biz.business_context.strip()]

    # Snippets are optional structured content blocks (e.g., rates, policies)
    for sn in biz.snippets.all():
        label = (sn.title or sn.key).title()
        parts += [f"\n### {label}", sn.content.strip()]

    if biz.blocked_keywords:
        parts += [f"\n### Restricted\nNever discuss: {', '.join(biz.blocked_keywords)}."]

    return "\n".join([p for p in parts if p])

def _ai_reply(biz: Business, user_msg: str) -> str:
    """Single-shot chat completion using the business-configured model settings."""
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
# Lightweight availability context (per sender)
# ---------------------------

def _avail_ctx_key(biz: Business, sid: str) -> str:
    return f"mbot:ctx:{biz.slug}:{sid}:avail"

def _set_avail_ctx(biz: Business, sid: str, ttl_minutes: int = 12):
    cache.set(_avail_ctx_key(biz, sid), True, ttl_minutes * 60)

def _has_avail_ctx(biz: Business, sid: str) -> bool:
    return bool(cache.get(_avail_ctx_key(biz, sid)))

def _clear_avail_ctx(biz: Business, sid: str):
    cache.delete(_avail_ctx_key(biz, sid))

# ---------------------------
# Intent detection: keywords / llm / hybrid
# ---------------------------

# Fast keyword list to cheaply catch clear booking intent.
_AVAIL_KW = [
    "available", "availability", "avail", "book", "booking", "reserve",
    "slot", "schedule", "pwede", "kaya", "bakante", "open", "free",
    "appointment", "haircut", "rent", "catering", "event", "reservation"
]

# “Now” words – separate because they’re strong signals even alone.
_NOW_RE = re.compile(r"\b(now( na)?|right now|ngayon( na)?)\b", re.I)

def _intent_mode(biz: Business) -> Literal["keyword", "llm", "hybrid"]:
    # Configure per business via availability_config.intent_mode
    cfg = getattr(biz, "availability_config", {}) or {}
    mode = (cfg.get("intent_mode") or "hybrid").lower()
    return mode if mode in {"keyword", "llm", "hybrid"} else "hybrid"

def _classify_intent_llm(biz: Business, text: str) -> Tuple[str, float]:
    """
    Use a tiny/cheap LLM to classify intent.
    Returns (label, confidence). Labels: 'availability', 'smalltalk', 'other'.
    """
    try:
        prompt = (
            "Classify the user's intent into one of: availability, smalltalk, other.\n"
            "Return a JSON object with keys: label, confidence (0..1). "
            "Examples that are 'availability': asking for open slots, booking, schedule, appointment, rental, reserve."
        )
        r = client.chat.completions.create(
            model="gpt-4o-mini",  # inexpensive / fast
            temperature=0.0,
            max_tokens=30,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": text},
            ],
        )
        raw = (r.choices[0].message.content or "").strip()
        # very light parse (avoid importing json here)
        label = "other"
        conf = 0.0
        m = re.search(r'"label"\s*:\s*"([^"]+)"', raw)
        if m: label = m.group(1).lower()
        m = re.search(r'"confidence"\s*:\s*([0-1](?:\.\d+)?)', raw)
        if m:
            try: conf = float(m.group(1))
            except Exception: pass
        return (label, conf)
    except Exception:
        log.exception("LLM intent classification error")
        return ("other", 0.0)

def _wants_availability(biz: Business, text: str, sender_id: str | None = None) -> bool:
    """
    Decide if the message should enter the availability flow.
    Modes:
      - 'keyword': cheap keyword+date/time heuristic only
      - 'llm': rely on LLM classifier (with context override)
      - 'hybrid': keyword/date/time OR (LLM with confidence >= 0.55)
    Also: if we just asked date/time (_has_avail_ctx), keep routing follow-ups here.
    """
    t = (text or "").lower()

    # If we recently asked for date/time, treat replies as availability (context stickiness).
    if sender_id and _has_avail_ctx(biz, sender_id):
        return True

    # Strong “now” trigger
    if _NOW_RE.search(t):
        return True

    # Date/time heuristic (we’ll reuse the strict parsers defined later)
    dt_hit = False
    try:
        # these are defined later in the file, so keep lazy import inside function
        if _parse_date_only(text, biz) or _parse_times(text):
            dt_hit = True
    except Exception:
        dt_hit = False

    mode = _intent_mode(biz)

    if mode in ("keyword", "hybrid"):
        if dt_hit or any(k in t for k in _AVAIL_KW):
            return True

    if mode in ("llm", "hybrid"):
        label, conf = _classify_intent_llm(biz, text)
        if label == "availability" and conf >= 0.55:
            return True

    return False
