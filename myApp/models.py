from django.db import models
from django.contrib.auth.models import User

class BusinessProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    business_name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    industry = models.CharField(max_length=100, choices=[
        ("Rental", "Rental"),
        ("Ecommerce", "Ecommerce"),
        ("Healthcare", "Healthcare"),
        ("Other", "Other"),
    ])
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.business_name

class ConnectedPage(models.Model):
    business = models.ForeignKey(BusinessProfile, on_delete=models.CASCADE)
    page_id = models.CharField(max_length=100)
    page_name = models.CharField(max_length=255)
    access_token = models.TextField()
    connected_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.page_name} ({'Active' if self.is_active else 'Inactive'})"

class FAQEntry(models.Model):
    business = models.ForeignKey(BusinessProfile, on_delete=models.CASCADE)
    question = models.TextField()
    answer = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.question[:50]

class BotSettings(models.Model):
    business = models.OneToOneField(BusinessProfile, on_delete=models.CASCADE)
    tone = models.CharField(max_length=50, choices=[
        ("formal", "Formal"),
        ("friendly", "Friendly"),
        ("taglish", "Taglish"),
    ], default="friendly")
    fallback_message = models.CharField(
        max_length=255,
        default="Sorry, I didn’t get that. Please contact our page directly."
    )
    is_muted = models.BooleanField(default=False)

    def __str__(self):
        return f"Settings for {self.business.business_name}"



class TrainingData(models.Model):
    business = models.ForeignKey('BusinessProfile', on_delete=models.CASCADE)
    file = models.FileField(upload_to='training_files/')
    description = models.TextField(blank=True)
    text_content = models.TextField(blank=True)  # ✅ Full extracted raw text
    summary_prompt = models.TextField(blank=True)  # ✅ Summarized prompt for AI reply
    is_processed = models.BooleanField(default=False)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.file.name} for {self.business.business_name}"
