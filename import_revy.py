#!/usr/bin/env python3
import os, sys, django

# 1) Point to your settings
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myProject.settings")

# 2) Initialize Django BEFORE importing models
django.setup()

# 3) Now it's safe to import your app models
from myApp.models import Business, Snippet

def env_or_prompt(env_key: str, prompt: str) -> str:
    v = os.getenv(env_key)
    if v: 
        print(f"{env_key} found in environment.")
        return v.strip()
    try:
        return input(prompt).strip()
    except KeyboardInterrupt:
        print("\nCancelled."); sys.exit(1)

def main():
    print("=== Revvy (Rent n' Rev) Onboarding ===")
    page_token = env_or_prompt("REVVY_PAGE_ACCESS_TOKEN", "Paste PAGE ACCESS TOKEN: ")
    verify_token = env_or_prompt("REVVY_VERIFY_TOKEN", "Choose/enter VERIFY TOKEN (used in Meta webhook): ")
    app_secret  = env_or_prompt("REVVY_APP_SECRET",  "Paste APP SECRET (for signature verification): ")

    biz, _ = Business.objects.update_or_create(
        slug="rentnrev",
        defaults=dict(
            name="Rent n' Rev",
            timezone="Asia/Manila",
            fb_page_access_token=page_token,
            fb_verify_token=verify_token,
            fb_app_secret=app_secret,
            model_name="gpt-4o-mini",
            temperature=0.4,
            max_tokens=300,
            system_prompt=(
                "You are Revvy, the virtual assistant of Rent n' Rev – a self-drive car rental based in Antipolo. "
                "Tone: polite, calm, composed (Taglish ok, no slang). Keep replies brief and solution-focused."
            ),
            business_context=(
                "Contact:\n- GCash: 0968 376 7376 – Anne Clemence Ocampo\n- GoTyme: 015905541183\n\n"
                "Vehicle availability:\n- Currently only 5-seater Mitsubishi Mirage."
            ),
            quick_replies=["Rates","Location","Reserve","Requirements"],
            blocked_keywords=[],
        )
    )

    snippets = {
        "location": "📍 406 Diamond Ln. Cristimar Village, Brgy. San Roque, Antipolo City",
        "rates": ("Self-drive within Metro Manila:\n- 12hrs – ₱1,499\n- 24hrs – ₱1,999\n\n"
                  "Outside Metro Manila:\n- 12hrs – ₱1,999\n- 24hrs – ₱2,499"),
        "reservation_policy": ("Reservation:\n- ₱500 deposit required; refundable after unit return.\n"
                               "- Payment methods: GCash (0968 376 7376 – Anne), GoTyme (015905541183)\n"
                               "- Ask only when needed: When? How many days? Preferred time/destination?"),
        "requirements": "Requirements:\n- Valid government ID\n- Driving license\n- Security deposit as advised",
    }
    for k, content in snippets.items():
        Snippet.objects.update_or_create(
            business=biz, key=k,
            defaults={"title": k.replace("_"," ").title(), "content": content}
        )

    print("\n✅ Revvy business saved.")
    print(f"   Verify Token: {biz.fb_verify_token}")
    print(f"   Callback URL: https://<your-domain>/messenger/{biz.slug}/webhook")

if __name__ == "__main__":
    main()
