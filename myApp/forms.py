from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class CustomSignupForm(UserCreationForm):
    full_name = forms.CharField(max_length=100, required=True)
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['full_name', 'email', 'password1', 'password2']



# forms.py

from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import UsernameField

class EmailOrUsernameAuthenticationForm(forms.Form):
    login = UsernameField(
        widget=forms.TextInput(attrs={"autofocus": True}),
        label="Email or Username"
    )
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput
    )

    def __init__(self, request=None, *args, **kwargs):
        self.request = request
        self.user_cache = None
        super().__init__(*args, **kwargs)

    def clean(self):
        login = self.cleaned_data.get('login')
        password = self.cleaned_data.get('password')

        if login and password:
            from django.contrib.auth.models import User
            try:
                user = User.objects.get(email__iexact=login)
                username = user.username
            except User.DoesNotExist:
                username = login

            self.user_cache = authenticate(self.request, username=username, password=password)
            if self.user_cache is None:
                raise forms.ValidationError("Invalid login credentials.")
            elif not self.user_cache.is_active:
                raise forms.ValidationError("This account is inactive.")

        return self.cleaned_data

    def get_user(self):
        return self.user_cache
