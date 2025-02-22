from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from django.contrib.auth import get_user_model
import json, re
from django.http import JsonResponse
from django.core.validators import validate_email, ValidationError
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login, authenticate, logout


User = get_user_model()

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

@csrf_exempt
def signup_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email', '').lower().strip()
            username = data.get('username', '').strip()
            password = data.get('password', '')
            if not all([email, username, password]):
                return JsonResponse({
                    'status' : 'error',
                    'message': 'All fields sre required'
                }, status=400)
            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Invalid email format'
                }, status=400)
            if User.objects.filter(email=email).exists()  :
                return JsonResponse({
                    'status': 'error',
                    'message': 'Email already exists'
                }, status=400)
            if len(username) < 3:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Username must be at least 3 characters long'
                }, status=400)                 
            if User.objects.filter(username=username).exists():
                return JsonResponse({
                    'status': 'error',
                    'message': 'Username already exists'
                }, status=400)   
    
            is_valid_password, password_message = validate_password(password)
            if not is_valid_password:
                return JsonResponse({
                    'status': 'error',
                    'message': password_message
                }, status=400)
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            return JsonResponse({
                'status': 'success',
                'message': 'User created successfully'
            }, status=201)
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': 'An unexpected error occurred'
            }, status=500)

@csrf_exempt
def signin_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')
            user = authenticate(username=username, password= password)
            if user and user.is_active :
                login(request, user)
                return JsonResponse({
                    'status' : 'success',
                     'message': 'User created successfully',
                    'user':{
                        'id' : user.id,
                        'username' : username
                    }
                })
            return JsonResponse({
                'status': 'error', 
                'message': 'Invalid credentials'
            }, status=401)
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error', 
                'message': 'Invalid JSON'
            }, status=400)
        
@csrf_exempt
def logout_view(request):
    if request.method == 'POST':
        request.session.flush() 
        logout(request) 
        return JsonResponse({'status': 'success'})