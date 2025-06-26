import fitz  # PyMuPDF
import docx
import os
from dotenv import load_dotenv

from django.conf import settings
import openai

# ✅ Use Railway or settings.py
openai.api_key = settings.OPENAI_API_KEY



def extract_text_from_pdf(file_path):
    text = ""
    with fitz.open(file_path) as doc:
        for page in doc:
            text += page.get_text()
    return text

def extract_text_from_docx(file_path):
    doc = docx.Document(file_path)
    return '\n'.join([para.text for para in doc.paragraphs])

def extract_text(file_field):
    file_path = file_field.path
    if file_path.endswith('.pdf'):
        return extract_text_from_pdf(file_path)
    elif file_path.endswith('.docx'):
        return extract_text_from_docx(file_path)
    else:
        return None  # Unsupported for now


import openai
from django.conf import settings

openai.api_key = settings.OPENAI_API_KEY

from .utils import extract_text  # make sure this exists

from .models import TrainingData
from django.conf import settings
import openai

openai.api_key = settings.OPENAI_API_KEY
def summarize_text_with_tone(text, tone="friendly", persona="Revvy"):
    messages = [
        {
            "role": "system",
            "content": f"""
You are {persona}, a helpful assistant for a business. Your tone is {tone}.
Below is a business document. Summarize it into helpful customer-facing notes.
Format your response as short bullet points or labeled sections. Only keep what’s useful for answering customer inquiries.

--- START OF DOCUMENT ---
{text}
--- END ---
"""
        }
    ]
    response = openai.ChatCompletion.create(  # ← use this for openai>=1.0
        model="gpt-4",
        messages=messages
    )
    return response.choices[0].message.content.strip()


def process_training_file(training_doc, tone="friendly", persona="Revvy"):
    try:
        file_path = training_doc.file.path
        text = extract_text(file_path)

        if not text:
            raise ValueError("Failed to extract text from file.")

        summary_prompt = summarize_text_with_tone(text, tone=tone, persona=persona)

        training_doc.text_content = text
        training_doc.summary_prompt = summary_prompt
        training_doc.is_processed = True
        training_doc.save()
    except Exception as e:
        print(f"🔥 Error processing training file: {e}")
        raise
