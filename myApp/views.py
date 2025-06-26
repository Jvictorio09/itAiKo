from django.shortcuts import render


import os
import openai  # 👈 Add this
from dotenv import load_dotenv

# Load .env file
dotenv_path = "C:/Users/ADMIN/Downloads/project/myProject/.env"
load_dotenv(dotenv_path)

openai_api_key = os.getenv("OPENAI_API_KEY")


openai.api_key = openai_api_key  # 👈 Set it here

from django.http import HttpResponse

def index(request):
    return HttpResponse("✅ Django app is working!")



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


from django.shortcuts import render, redirect
from django.contrib.auth import login
from .forms import CustomSignupForm
from .models import BusinessProfile, BotSettings

def signup_view(request):
    if request.method == 'POST':
        form = CustomSignupForm(request.POST)
        if form.is_valid():
            # Save the user (creates password hash, etc.)
            user = form.save(commit=False)
            user.email = form.cleaned_data.get('email')
            
            full_name = form.cleaned_data.get('full_name')
            user.first_name = full_name.split(' ')[0]
            user.last_name = ' '.join(full_name.split(' ')[1:]) if len(full_name.split(' ')) > 1 else ''
            user.save()

            # Create BusinessProfile with description
            business = BusinessProfile.objects.create(
                user=user,
                business_name=form.cleaned_data.get('business_name'),
                industry=form.cleaned_data.get('industry'),
                description=form.cleaned_data.get('description') or ""
            )

            # Create BotSettings with default tone
            BotSettings.objects.create(
                business=business,
                tone="friendly"
            )

            # After login
            login(request, user)
            request.session['show_welcome_modal'] = True  # Set flag
            return redirect('dashboard')

    else:
        form = CustomSignupForm()

    return render(request, 'myApp/signup.html', {'form': form})




from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('dashboard')  # Replace with your dashboard URL name
    else:
        form = AuthenticationForm()
    
    return render(request, 'myApp/login.html', {'form': form})

from django.contrib.auth import logout
from django.shortcuts import redirect
from django.contrib import messages

def custom_logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect('login')  # Or your landing page

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .models import BusinessProfile, BotSettings, ConnectedPage, TrainingData


from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .models import BusinessProfile, BotSettings, ConnectedPage, TrainingData
from .utils import process_training_file  # ✅ New summarizer

@login_required
def dashboard_view(request):
    business = BusinessProfile.objects.filter(user=request.user).first()
    if not business:
        return redirect('signup')  # Fallback if no profile found

    settings = BotSettings.objects.filter(business=business).first()
    page = ConnectedPage.objects.filter(business=business).first()
    training_docs = TrainingData.objects.filter(business=business)

    if request.method == 'POST':
        if 'update_profile' in request.POST:
            business.business_name = request.POST.get('business_name', business.business_name)
            business.industry = request.POST.get('industry', business.industry)
            business.description = request.POST.get('description', business.description)
            business.save()

        elif 'upload_training' in request.POST and request.FILES.get('training_file'):
            file = request.FILES['training_file']
            training_doc = TrainingData.objects.create(
                business=business,
                file=file,
                description=request.POST.get('file_description', '')
            )

            try:
                # ✅ Summarize file for AI use
                tone = settings.tone if settings and settings.tone else "friendly"
                process_training_file(training_doc, tone=tone, persona="Revvy")
            except Exception as e:
                print(f"⚠️ Error summarizing training file: {e}")

    return render(request, 'myApp/dashboard.html', {
        'business': business,
        'settings': settings,
        'page': page,
        'training_docs': training_docs,
    })


from .models import TrainingData
import openai
from django.conf import settings

openai.api_key = settings.OPENAI_API_KEY

def reply_to_customer(recipient_id, user_message, business):
    latest_doc = TrainingData.objects.filter(business=business, is_processed=True).last()
    prompt = latest_doc.summary_prompt if latest_doc else "You are a helpful assistant."

    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": user_message}
    ]

    try:
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=messages
        )
        reply = response.choices[0].message.content.strip()
    except Exception as e:
        print(f"🔥 OpenAI error: {e}")
        reply = "Oops! I had trouble thinking that through. Please try again."

    return reply
