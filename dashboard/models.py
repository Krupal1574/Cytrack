from django.db import models

class Incident(models.Model):
    category = models.CharField(max_length=255)
    count = models.IntegerField()