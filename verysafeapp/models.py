from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Secret(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    secret = models.TextField()
    
    def __str__(self):
         return f"Secret by {self.user.username}"
