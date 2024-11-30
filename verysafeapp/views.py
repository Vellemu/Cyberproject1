from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.db import connection
from .models import Secret


def homeView(request):
    return render(request, "verysafeapp/home.html")

# Flaw: csrf_exempt is used to disable the protection
# Fix: Enable csrf protection for the registerView.
@csrf_exempt 
def registerView(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
        else:
            # Flaw: The password is stored in plaintext so the flaw is Cryptographic Failures number 2 from the 2021 list.
            user = User(username=username, password=password)
            user.save()
            # Fix: The password should be hashed before storing it in the database. Using djangos create_user method or making a own method to hash the password.
            # Secure code: user = User.objects.create_user(username=username, password=password)
            messages.success(request, 'User created successfully')
            return redirect('homeView')
    return redirect('homeView')

# Flaw: csrf_exempt is used to disable the protection
# Fix: Enable csrf protection for the loginView.
@csrf_exempt
def loginView(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        # Flaw: Identification and Authentication Failures number 7 from the 2021 list.
        user = User.objects.get(username=username, password=password)
        # Fix: To fix this flaw we should use Djangos authenticate method to authenticate and secure the credntial comparisation
        # Secure code: user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            secrets = Secret.objects.filter(user=user)
            return render(request, 'verysafeapp/profile.html', {'username': username, 'secrets': secrets}) # Passes the username and secrets so they are loaded to the hmlt page also. So page says "Welcome "username"
        else:
            messages.error(request, 'Invalid username or password')
    return redirect('homeView')

#First flaw in the function Broken Acces control number 1 in the list: even thought the function handles secrets
#inside the function, it does not require the user to be logged in. So this could be exploited if a hacker finds way to the profile site.
# Fix: Add @login_required so the usage of function is limited to the user who is logged in his profile page.
@csrf_protect 
#Function to add secret using POST method
def addSecret(request):
    if request.method == "POST":
        secret = request.POST.get('secret')
        user_id = request.user.id
        # Flaw: addSecret has signicant flaw. It is vulnerable to SQL injection attacks, which is categorized under number 3 of the 2021 list "Injection".
        # Fix: We can fix this flaw using Djangos ORM to insert the data to the database
        # Secure code: Secret.objects.create(user=request.user, secret=secret)
        # Or we can use %s in place of the variables and get the variables from parameters.
        with connection.cursor() as cursor:
            cursor.execute(f"INSERT INTO verysafeapp_secret (user_id, secret) VALUES ({user_id}, '{secret}')")
        messages.success(request, 'Secret added successfully')
        secrets = Secret.objects.filter(user=request.user)
        return render(request, 'verysafeapp/profile.html', {'username': request.user.username, 'secrets': secrets})
    return redirect('homeView')


#logout functio for user friendlines. No security flaws here.
@csrf_protect
@login_required
def logoutView(request):
    logout(request)
    return redirect('homeView')