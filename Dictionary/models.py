from django.db import models

class Dictionary(models.Model):
    english = models.CharField(max_length=100)
    persian = models.CharField(max_length=100)
    description = models.CharField(max_length=3000)
    addedUser = models.CharField(max_length=100)
