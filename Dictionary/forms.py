from django import forms
from captcha.fields import CaptchaField
from .models import Dictionary
from django.forms import ModelForm
from Dictionary.models import Dictionary


class CaptchaTestForm(forms.Form):
    captcha = CaptchaField()


class EmailForm(forms.Form):
    email = forms.EmailField()


class AddWord(forms.Form):
    english = forms.CharField(max_length=100)
    persian = forms.CharField(max_length=100)
    description = forms.CharField(max_length=3000)

