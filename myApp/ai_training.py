import openai
import faiss
import os
import json
from .utils import extract_text
from django.conf import settings
import numpy as np


openai.api_key = settings.OPENAI_API_KEY

def chunk_text(text, chunk_size=500):
    words = text.split()
    return [' '.join(words[i:i+chunk_size]) for i in range(0, len(words), chunk_size)]

def get_embeddings(chunks):
    return [openai.Embedding.create(input=chunk, model="text-embedding-3-small")['data'][0]['embedding'] for chunk in chunks]

def train_on_file(training_file):
    # Extract raw text
    raw_text = extract_text(training_file.file)
    if not raw_text:
        return None

    chunks = chunk_text(raw_text)
    vectors = get_embeddings(chunks)

    dim = len(vectors[0])
    index = faiss.IndexFlatL2(dim)
    index.add(np.array(vectors).astype('float32'))

    # Save locally (could push to S3/Drive later)
    folder = f"training_indexes/{training_file.id}"
    os.makedirs(folder, exist_ok=True)
    faiss.write_index(index, f"{folder}/index.faiss")

    with open(f"{folder}/chunks.json", "w") as f:
        json.dump(chunks, f)

    return True
