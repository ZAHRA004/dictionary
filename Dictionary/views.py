from pydoc import describe
from symtable import Class
import random
import string
import hashlib
import os
import base64

from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, logout, authenticate
from .forms import *
from .models import *
from django.core.mail import send_mail
from django.contrib.auth.models import User
from FinalProject.settings import EMAIL_HOST_USER
from django.db.models import Q
from django.contrib import messages
from django.utils.timezone import now
from datetime import datetime
from django.contrib.admin.views.decorators import staff_member_required
import secrets
from datetime import timedelta, datetime
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import make_password


def IntroView(request):
    return render(request, 'dictionary/intro.html', {})


def SignupView(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        
        if username and email and password1 and password2 and (password1 == password2) and not (User.objects.filter(username=username).exists()) and not (User.objects.filter(email=email).exists()) :
            if len(password1) < 8 :
                messages.error(request, "password must be 8 or more caracter")
                return render(request, 'dictionary/signup.html' )
            user = User.objects.create(
            username=username,
            email=email,
            password=make_password(password1))
            messages.success(request, "Your account has been created successfully!")
            return redirect('login')
        else:
            if password1 != password2 :
                messages.error(request, "Passwords do not match!")
                return render(request, 'dictionary/signup.html' )

            if User.objects.filter(username=username).exists():
                messages.error(request, "Username already exists!")
                return render(request, 'dictionary/signup.html' )

            if User.objects.filter(email=email).exists():
                messages.error(request, "Email already exists!")
                return render(request, 'dictionary/signup.html' )

    return render(request, 'dictionary/signup.html' )

def LoginView(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        captcha_form = CaptchaTestForm(request.POST)
        if form.is_valid() and captcha_form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('/login/home')
        else:
            return render(request, 'dictionary/login.html', {'form': form, 'captcha': captcha_form})
    else:
        form = AuthenticationForm() #<<<<<<< HEAD
        captcha_form = CaptchaTestForm()
        
    return render(request, 'dictionary/login.html', {'form': form, 'captcha': captcha_form})

#def generate_reset_token(user):
#    token = secrets.token_urlsafe(32)
#    user.reset_token = token
#    user.reset_token_expiry = datetime.now() + timedelta(hours=1)  # Token valid for 1 hour
#    user.save()
#    return token
#def send_reset_email(user , email):
#    token = generate_reset_token(user)
#    reset_url = f"http://127.0.0.1:8000/reset-password/{token}/"
#    send_mail(
#        'Password Reset Request',
#        f'Click the link to reset your password: {reset_url}',
#        EMAIL_HOST_USER,
#        [email],
#        fail_silently=True
#    )

def generate_random_password():
    COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "12345678",
    "111111", "123123", "abc123", "password1", "1234"}
    while True:
        password =  ''.join(random.choices( string.ascii_letters + string.digits + 
                            string.punctuation,k=random.randint(8, 12) ))
        if ( len(password) >= 8 and not password.isdigit() and password not in COMMON_PASSWORDS):
            return password
#>>>>>>> 377e6ad89c9e9aa85b006810e38c9f33fc398202

def hash_password_pbkdf2_sha256(password, iterations=870000):
    salt = base64.b64encode(os.urandom(16)).decode('utf-8')
    dk = hashlib.pbkdf2_hmac(
        hash_name='sha256',           
        password=password.encode(),   
        salt=salt.encode(),           
        iterations=iterations         
    )
    hashed_password = base64.b64encode(dk).decode('utf-8')
    return  f"pbkdf2_sha256${iterations}${salt}${hashed_password}"
    
def ForgotPasswordView(request):
    if request.method == 'POST':
        form = EmailForm(request.POST)
        if form.is_valid():
            email = request.POST.get('email')
            try:
                user = User.objects.all().get(email=email)
                #send_reset_email(user , user.email)
                newPassword = generate_random_password()
                hashed = hash_password_pbkdf2_sha256(newPassword)
                user.password = hashed
                user.save()
                send_mail(
                    'Password Reset Request',
                    f'your password: {newPassword}',
                    EMAIL_HOST_USER,
                    [email],
                    fail_silently=True
                )
                return render(request, 'PasswordResetDone.html')
            except:
                return render(request, 'PasswordResetEmailNotFound.html')
    form = EmailForm()
    return render(request, 'forgotPassword.html' , {'form': form})

#def reset_password(request, token):
#    try:
#        user = User.objects.get(reset_token=token, reset_token_expiry__gte=datetime.now())
#    except User.DoesNotExist:
#        return render(request, 'invalid_token.html')

#    if request.method == 'POST':
#        new_password = request.POST.get('password')
#        user.password = make_password(new_password)
#        user.reset_token = None 
#        user.reset_token_expiry = None
#        user.save()
#        return redirect('login')  

#    return render(request, 'reset_password.html')


def LogoutView(request):
    logout(request)
    return redirect('/login')



def HomeView(request):
    if request.user.is_authenticated:
        last_activity = request.session.get('last_activity')
        if last_activity:
            last_activity = datetime.fromisoformat(last_activity)
            elapsed_time = (datetime.now() - last_activity).total_seconds()
            if elapsed_time > 20:
                del request.session['last_activity']
                return redirect('login')
        request.session['last_activity'] = datetime.now().isoformat()

    query = request.GET.get('q', '')

    if request.method == 'POST':
        # delete
        if 'delete_word' in request.POST:
            word_id = request.POST.get('delete_word')
            word = get_object_or_404(Dictionary, id=word_id, addedUser=request.user)
            word.delete()
            return redirect('home')

        # edit
        if 'edit_word' in request.POST:
            word_id = request.POST.get('edit_word')
            word = get_object_or_404(Dictionary, id=word_id, addedUser=request.user)
            word.english = request.POST.get('english')
            word.persian = request.POST.get('persian')
            word.description = request.POST.get('description')
            word.save()
            return redirect('home')

        # add
        form = AddWord(request.POST)
        if form.is_valid():
            dic = Dictionary(
                english=request.POST.get('english'),
                persian=request.POST.get('persian'),
                description=request.POST.get('description'),
                addedUser=request.user
            )
            dic.save()
            return redirect('home')
    else:
        form = AddWord()

    # words
    words = Dictionary.objects.filter(addedUser=request.user)
    if query:
        words = words.filter(
            Q(english__icontains=query) | Q(persian__icontains=query)
        )

    return render(request, 'dictionary/home.html', {'form': form, 'words': words, 'query':query})


@staff_member_required
def AdminPanelView(request):
    # all users
    total_users = User.objects.count()

    # all words
    total_words = Dictionary.objects.count()

    # words for each user
    users_data = []
    for user in User.objects.all():
        user_words_count = Dictionary.objects.filter(addedUser=user).count()
        users_data.append({
            'username': user.username,
            'word_count': user_words_count
        })

    # sort
    users_data = sorted(users_data, key=lambda x: x['word_count'], reverse=True)

    # chart
    chart_labels = [user['username'] for user in users_data]
    chart_data = [user['word_count'] for user in users_data]

    return render(request, 'adminPanel.html', {
        'total_users': total_users,
        'total_words': total_words,
        'users_data': users_data,
        'chart_labels': chart_labels,
        'chart_data': chart_data
    })