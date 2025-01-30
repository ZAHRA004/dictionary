from pydoc import describe
from symtable import Class

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

def SignupView(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        email_form = EmailForm(request.POST)

        if form.is_valid() and email_form.is_valid():
            user = form.save()
            user.email = email_form.cleaned_data['email']
            user.save()
            return redirect('/login')
        else:
            return render(request, 'dictionary/login.html', {'form': form, 'email': email_form})

    else:
        form = UserCreationForm()
        email_form = EmailForm()

    return render(request, 'dictionary/login.html', {'form': form, 'email': email_form})

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
            return render(request, 'dictionary/login.html', {'form': form, 'captcha': captcha_form})  # استفاده از captcha_form
    else:
        form = AuthenticationForm()
        captcha_form = CaptchaTestForm()
    return render(request, 'dictionary/login.html', {'form': form, 'captcha': captcha_form})  # استفاده از captcha_form

def ForgotPasswordView(request):
    if request.method == 'POST':
        form = EmailForm(request.POST)
        if form.is_valid():
            try:
                user = User.objects.all().get(email=request.POST.get('email'))
                send_mail(
                    'forgot password',
                    "jjjjjjjjjjjjjjjjjjj",
                    EMAIL_HOST_USER,
                    [request.POST.get('email')], fail_silently=True)
                return redirect('/forgotPassword/done')
            except:
                return HttpResponse('this email does not exist')

    else:
        form = EmailForm()
    return render(request, 'dictionary/forgotPassword.html', {'form': form})


def passwordResetDoneView(request):
    return render(request, 'dictionary/passwordResetDone.html', {})


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