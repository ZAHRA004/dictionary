from django.db import models
from django.contrib.auth.models import User

class Dictionary(models.Model):
    english = models.CharField(max_length=100)
    persian = models.CharField(max_length=100)
    description = models.CharField(max_length=3000)
    addedUser = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.english


class Word(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    word = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.word


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username