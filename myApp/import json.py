import json
import requests
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

VERIFY_TOKEN = 'rentnrev123'
PAGE_ACCESS_TOKEN = 'AAPRojz24LUBO8lhyF3y75LFOCTHbu2TYjpeIl3apWf25i8sBbSIakRLS8XYX48PDnEZA3XY4V1XmwUCzXjHfnh3NGS3JbZB8pCZCd1rp6hM762Brmd5JKph5VuHZBD9ZCzobyfRf6mc7ZCr0Gbuw5oZAHWOu5uyvdKvrFvCvx0FpntYOb5znVPHioJ00ud5vM1chTxZBhOt3QZDZD'

from datetime import datetime, timedelta

# Mute map to track muted users by sender_id
REVVY_MUTE_MAP = {}

@csrf_exempt
def webhook(request):
    if request.method == 'GET':
        token = request.GET.get('hub.verify_token')
        challenge = request.GET.get('hub.challenge')
        if token == VERIFY_TOKEN:
            return HttpResponse(challenge)
        return HttpResponse('Verification token mismatch', status=403)

    elif request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))

        for entry in data.get('entry', []):
            for event in entry.get('messaging', []):
                sender_id = event['sender']['id']
                message_text = event.get('message', {}).get('text')

                if not message_text:
                    continue

                msg_lower = message_text.lower().strip()

                # ⏸️ Handle #manual first
                if msg_lower.startswith("#manual"):
                    REVVY_MUTE_MAP[sender_id] = datetime.now() + timedelta(minutes=5)
                    print(f"Revvy muted for 5 minutes for {sender_id}")

                    manual_reply = message_text[len("#manual"):].strip()
                    if manual_reply:
                        send_manual_reply(sender_id, manual_reply)

                    return HttpResponse("Manual reply sent + Revvy muted", status=200)

                # ⛔ Handle #revvy_off
                if msg_lower.startswith("#revvy_off"):
                    REVVY_MUTE_MAP[sender_id] = datetime.max
                    print(f"Revvy turned off indefinitely for {sender_id}")
                    return HttpResponse("Revvy turned off", status=200)

                # ⏱️ Check mute status
                mute_until = REVVY_MUTE_MAP.get(sender_id)
                if mute_until and mute_until > datetime.now():
                    print(f"Revvy is currently muted for {sender_id} until {mute_until}")
                    return HttpResponse("Revvy is muted", status=200)

                # 🤖 Default: Revvy replies
                reply_to_user(sender_id, message_text)

        return HttpResponse('ok', status=200)



# ⬇️ Manual reply sender
def send_manual_reply(recipient_id, message_text):
    url = f"https://graph.facebook.com/v17.0/me/messages?access_token={PAGE_ACCESS_TOKEN}"
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": message_text}
    }
    headers = {'Content-Type': 'application/json'}
    requests.post(url, json=payload, headers=headers)

# 🤖 Revvy's brain
from openai import OpenAI
client = OpenAI(api_key=openai_api_key)

def reply_to_user(recipient_id, user_message):
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": """
You are Revvy, the virtual assistant of Rent n' Rev – a self-drive car rental based in Antipolo. Your tone is polite, calm, and composed — Taglish is okay, but avoid slang or "pa-cool" expressions. You're here to assist professionally, not casually.

Speak how Anne Clemence or Julia would: clear, honest, approachable, and always straight to the point. Be respectful at all times and reply briefly unless more info is needed. Do not use phrases like “G ka na?”, “pasyal kayo”, or unnecessary emojis. You are not here to entertain — you are here to assist.

Here are specific responses and context:

If asked for **location**:
📍 406 Diamond Ln. Cristimar Village, Brgy. San Roque, Antipolo City

If asked for **rates**:
Self-drive within Metro Manila:  
📌 12hrs – ₱1,499  
📌 24hrs – ₱1,999  

Outside Metro Manila:  
📌 12hrs – ₱1,999  
📌 24hrs – ₱2,499  

If asked about **6-pax vehicle**:
Currently, only 5-seater Mitsubishi Mirage is available. Do not promise other units unless confirmed.

For **reservations**:
₱500 deposit required. Refundable after unit return.  
Payment methods:  
GCash: 0968 376 7376 – Anne Clemence Ocampo  
GoTyme: 015905541183

Ask only when needed:
- "For when po ang rental?"
- "Ilang days po kukunin n’yo?"
- "May preferred time or destination po kayo?"

Avoid generic greetings. Always aim to solve or clarify.

Keep answers short and smart. You're here to make their decision easier.
"""},
                {"role": "user", "content": user_message}
            ]
        )
        gpt_reply = response.choices[0].message.content.strip()
    except Exception as e:
        print("🔥 OpenAI Error:", e)
        gpt_reply = "Oops! Something went wrong while thinking."

    url = f"https://graph.facebook.com/v17.0/me/messages?access_token={PAGE_ACCESS_TOKEN}"
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": gpt_reply}
    }
    headers = {'Content-Type': 'application/json'}
    requests.post(url, headers=headers, json=payload)