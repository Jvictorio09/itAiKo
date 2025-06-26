from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class CustomSignupForm(UserCreationForm):
    full_name = forms.CharField(max_length=100, required=True)
    email = forms.EmailField(required=True)
    business_name = forms.CharField(max_length=100, required=True)
    industry = forms.ChoiceField(choices=[
        ('Rental', 'Rental'),
        ('Ecommerce', 'Ecommerce'),
        ('Healthcare', 'Healthcare'),
        ('Other', 'Other')
    ])
    description = forms.CharField(widget=forms.Textarea, required=False)

    class Meta:
        model = User
        fields = ['full_name', 'email', 'password1', 'password2', 'business_name', 'industry', 'description']
