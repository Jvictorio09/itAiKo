import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myProject.settings")
django.setup()

from myApp.models import Business

b = Business.objects.get(slug="rentnrev")
print("Slug:", b.slug)
print("VERIFY TOKEN:", b.fb_verify_token)
print(f"Callback URL: https://https://k5177qxt-8080.asse.devtunnels.ms/messenger/{b.slug}/webhook")
