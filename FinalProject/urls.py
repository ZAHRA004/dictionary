"""
URL configuration for FinalProject project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path , include
from Dictionary.views import *
urlpatterns = [
    #    path('admin/', admin.site.urls),
    path('' , IntroView , name = 'intro') ,
    path('admin/', admin.site.urls),
    path('admin-panel/', AdminPanelView, name='adminPanel'),
    path('captcha/', include('captcha.urls')),
    path('login/' , LoginView , name = 'login'),
    path('signup/' , SignupView , name='signup'),
    path('login/home' , HomeView , name = 'home') ,
    path('logout/' , LogoutView , name = 'logout'),
    path('forgotPassword/' , ForgotPasswordView , name = 'forgotPassword'),
    #path('reset-password/<str:token>/', reset_password, name='reset_password')
]
