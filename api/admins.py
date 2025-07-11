from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from datetime import datetime, timedelta
from django.contrib.auth.hashers import make_password, check_password
from pymongo import MongoClient
from django.core.mail import send_mail
from bson import ObjectId
from dotenv import load_dotenv
from django.utils.crypto import get_random_string
import os
import json
import jwt
import random
import string
import secrets
from django.utils import timezone
import re
import logging
import jwt
import urllib.parse
from django.conf import settings

logger = logging.getLogger(__name__)

load_dotenv()

JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'

# Connect to MongoDB
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["Leaderboard"]
mapped_events_collection = db['Mapped_Events']
superadmin_collection = db["superadmin"]
users_collection = db["users"]
points_collection = db['Points']
tasks_collection = db['events']
admin_collection = db["admin"]


def generate_verification_code():
    """Generate a random 6-digit verification code."""
    return ''.join(random.choices(string.digits, k=6))

def store_verification_code(email, code):
    """Store verification code with expiry time (10 minutes)."""
    expiry_time = datetime.now() + timedelta(minutes=10)
    admin_collection.update_one(
        {'email': email},
        {
            '$set': {
                'verification_code': code,
                'verification_expiry': expiry_time,
                'verification_attempts': 0
            }
        }
    )

def is_valid_verification_code(email, code):
    """Check if verification code is valid and not expired."""
    admin = admin_collection.find_one({'email': email})
    if not admin or 'verification_code' not in admin:
        return False

    if admin['verification_expiry'] < datetime.now():
        return False

    if admin.get('verification_attempts', 0) >= 3:  # Limit attempts
        return False

    # Increment attempts
    admin_collection.update_one(
        {'email': email},
        {'$inc': {'verification_attempts': 1}}
    )

    return admin['verification_code'] == code

def reset_login_attempts(email):
    """Reset login attempts for a given email."""
    admin_collection.update_one(
        {'email': email},
        {
            '$set': {
                'login_attempts': 0
            }
        }
    )

def increment_login_attempts(email):
    """Increment login attempts and set account to Inactive if threshold reached."""
    admin = admin_collection.find_one({'email': email})
    current_attempts = admin.get('login_attempts', 0) + 1
    account_deactivated = False

    if current_attempts >= 3:  # Deactivation threshold
        # Deactivate the account instead of using a time-based lockout
        admin_collection.update_one(
            {'email': email},
            {
                '$set': {
                    'login_attempts': current_attempts,
                    'status': 'Inactive'
                }
            }
        )
        account_deactivated = True
    else:
        admin_collection.update_one(
            {'email': email},
            {
                '$set': {
                    'login_attempts': current_attempts
                }
            }
        )
    return current_attempts, account_deactivated

def check_account_status(email):
    """Check if account is deactivated."""
    admin = admin_collection.find_one({'email': email})
    if not admin:
        return False

    return admin.get('status') == 'Inactive'

#======================================================= FUNCTIONS ===========================================================================

def generate_tokens(name, email,Admin_ID):
    """Generates JWT tokens for admin authentication.

    Args:
        name (str): The admin user's name.

    Returns:
        dict: A dictionary containing the JWT token.
    """
    payload = {
        'name': name,
        'email': email,
        'admin_id': str(Admin_ID),  # Convert ObjectId to string
        "exp": datetime.utcnow() + timedelta(days=1),
        "iat": datetime.utcnow(),
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {'jwt': token}

#======================================================= ADMIN ===========================================================================
def generate_secure_token(length=32):
    """Generate a secure random token."""
    if length <= 0:
        raise ValueError("Token length must be positive")
    alphabet = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(alphabet) for _ in range(length))
    if not token:
        raise ValueError("Failed to generate token")
    return token

def validate_token(token):
    """Validate the token and check if it has expired."""
    admin_user = admin_collection.find_one({'password_setup_token': token})
    if not admin_user:
        return False, "Invalid token"

    if datetime.now() > admin_user['password_setup_token_expiry']:
        return False, "Token has expired"

    return True, "Token is valid"

def setup_password(token, password):
    """Set the user's password and invalidate the token."""
    is_valid, message = validate_token(token)
    if not is_valid:
        return False, message

    # Validate password complexity
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"

    # Hash the password and update the admin user
    hashed_password = make_password(password)
    for user in admin_collection:
        if user['password_token'] == token:
            user.update({
                'password': hashed_password,
                'password_set': True,
                'password_token': None,
                'token_expiry': None,
                'status': "Active"
            })
            break

    return True, "Password set successfully"

@csrf_exempt
def admin_signup(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            name = data.get('name')
            email = data.get('email')

            if not all([name, email]):
                return JsonResponse({'error': 'Name and email are required'}, status=400)

            # Check if the email is already assigned to an admin
            if admin_collection.find_one({'email': email}):
                return JsonResponse({'error': 'Email already assigned to an admin'}, status=400)

            # Generate a secure, one-time token for password setup
            token = get_random_string(length=32)
            expiry_time = timezone.now() + timedelta(minutes=30)

            # Create the admin user with pending password setup
            admin_user = {
                'name': name,
                'email': email,
                'password_set': False,
                'password_setup_token': token,
                'password_setup_token_expiry': expiry_time,
                'status': "Active",
                'created_at': datetime.now(),
                'last_login': None
            }

            result = admin_collection.insert_one(admin_user)

            # Send the secure, one-time link to set the password
            setup_link = f'https://snsct-dt-leaderboard.vercel.app/admin/setup-password?token={token}'
            send_mail(
                subject='Set your password for AI exam analyzer',
                message=f"""
                Hi {name},

                Your Admin account has been created successfully.

                Please click the following link to set your password: {setup_link}
                This link will expire in 30 minutes.

                Best regards,
                SuperAdmin Team
                """,
                from_email=None,  # Uses DEFAULT_FROM_EMAIL
                recipient_list=[email],
                fail_silently=False,
            )

            return JsonResponse({'message': 'Admin registered successfully. Please check your email to set your password.'}, status=201)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def validate_password_setup_token(request):
    if request.method == "GET":
        try:
            token = request.GET.get('token')

            if not token:
                return JsonResponse({'error': 'Token is required'}, status=400)

            # Check if the token is valid and not expired
            admin_user = admin_collection.find_one({
                'password_setup_token': token,
                'password_setup_token_expiry': {'$gt': timezone.now()}
            })

            if not admin_user:
                return JsonResponse({'error': 'Invalid or expired token'}, status=400)

            return JsonResponse({'message': 'Token is valid'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def set_password(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            token = data.get('token')
            password = data.get('password')

            if not all([token, password]):
                return JsonResponse({'error': 'Token and password are required'}, status=400)

            # Check if the token is valid and not expired
            admin_user = admin_collection.find_one({
                'password_setup_token': token,
                'password_setup_token_expiry': {'$gt': timezone.now()}
            })

            if not admin_user:
                return JsonResponse({'error': 'Invalid or expired token'}, status=400)

            # Check password complexity (8+ characters, at least one uppercase, one lowercase, one digit)
            if len(password) < 8:
                return JsonResponse({'error': 'Password must be at least 8 characters long'}, status=400)

            if not any(char.isupper() for char in password):
                return JsonResponse({'error': 'Password must contain at least one uppercase letter'}, status=400)

            if not any(char.islower() for char in password):
                return JsonResponse({'error': 'Password must contain at least one lowercase letter'}, status=400)

            if not any(char.isdigit() for char in password):
                return JsonResponse({'error': 'Password must contain at least one digit'}, status=400)

            # Hash the password and update the admin user
            hashed_password = make_password(password)
            admin_collection.update_one(
                {'_id': admin_user['_id']},
                {
                    '$set': {
                        'password': hashed_password,
                        'password_set': True,
                        'password_setup_token': None,
                        'password_setup_token_expiry': None
                    }
                }
            )

            return JsonResponse({'message': 'Password set successfully. You can now log in.'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def password_setup(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            token = data.get('token')
            password = data.get('password')

            success, message = setup_password(token, password)
            if success:
                return JsonResponse({'message': message}, status=200)
            else:
                return JsonResponse({'error': message}, status=400)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def admin_signin(request):
    """Authenticates an admin user and generates a JWT token.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing the JWT token or an error message.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            if not email:
                return JsonResponse({'error': 'Email is required'}, status=400)

            if not password:
                return JsonResponse({'error': 'Password is required'}, status=400)            # Check if account is deactivated
            if check_account_status(email):
                return JsonResponse(
                    {'error': 'Account has been deactivated due to too many failed login attempts. Contact the administrator.'},
                    status=403)
                    
            admin_user = admin_collection.find_one({'email': email})

            if not admin_user:
                return JsonResponse(
                    {'error': f'Invalid email. No account found with email: {email}'}, status=401)

            # Check if admin status is Active
            if admin_user.get('status') != 'Active':
                return JsonResponse(
                    {'error': 'Account is inactive. Contact the administrator.'}, status=403)

            if not admin_user.get('password') or not admin_user.get('email'):
                return JsonResponse(
                    {'error': 'Invalid admin user data'}, status=500)

            if not check_password(password, admin_user['password']):
                attempts, account_deactivated = increment_login_attempts(email)
                if account_deactivated:
                    return JsonResponse(
                        {'error': 'Account has been deactivated due to too many failed attempts. Contact the administrator.'},
                        status=403)
                return JsonResponse(
                    {'error': f'Invalid password. {3 - attempts} attempts remaining before account deactivation'},
                    status=401)

            # Success - reset login attempts and generate token
            reset_login_attempts(email)
            token = generate_tokens(admin_user['name'], admin_user['email'], admin_user['Admin_ID'])
            print('Generated token:', token['jwt'])  # Debug

            # Update last login time
            admin_collection.update_one(
                {'_id': admin_user['_id']},
                {'$set': {'last_login': datetime.now()}}
            )

            return JsonResponse({
                'message': 'Logged in successfully',
                'jwt': token['jwt'],
                'email': email,
                'name': admin_user.get("name"),
                'admin_id': str(admin_user['Admin_ID']),
                'last_login': datetime.now(),
            }, status=200)


        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format in request body'}, status=400)

        except Exception as e:
            return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def list_assigned_students(request):
    """
    Lists students assigned to admin based on JWT token (no manual admin_id needed).
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        # Read JWT token from header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({"error": "Authorization header missing or invalid"}, status=401)

        token = auth_header.split(' ')[1]

        # Decode token
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        # Get admin email from token
        admin_email = decoded.get("email")
        if not admin_email:
            return JsonResponse({"error": "Invalid token payload"}, status=400)

        # Use the correct admin collection name
        admin_collection = db["Admin"]

        # Find admin by email
        admin = admin_collection.find_one({'email': admin_email})
        if not admin:
            return JsonResponse({"error": "Admin not found"}, status=404)

        # Check actual field name for admin_id (case-sensitive!)
        admin_code = admin.get("admin_id") or admin.get("Admin_ID") or admin.get("AdminId")
        if not admin_code:
            return JsonResponse({"error": "admin_id missing in admin record"}, status=500)

        # Find students assigned to this admin_id
        users_collection = db["Students_Data"]
        students = list(users_collection.find({"admin_id": admin_code}))

        if not students:
            return JsonResponse({"message": "No students found for this admin."}, status=404)

        # Serialize students
        student_list = []
        for s in students:
            s['_id'] = str(s['_id'])
            student_list.append(s)

        return JsonResponse({
            "message": f"Found {len(student_list)} students assigned to admin.",
            "students": student_list
        }, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "Invalid token"}, status=401)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)
        
@csrf_exempt
def fetch_tasks_grouped_by_event(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            admin_name = data.get('admin_name')
            admin_id = data.get('admin_id')

            print("📩 Received admin_name from frontend:", admin_name)
            print("📩 Received admin_id from frontend:", admin_id)

            if not admin_name or not admin_id:
                return JsonResponse({"error": "Admin name and Admin ID are required"}, status=400)

            # ✅ Match an object inside the assigned_to array
            documents = list(users_collection.find({
                "assigned_to": {
                    "$elemMatch": {
                        "name": admin_name,
                        "admin_id": admin_id
                    }
                }
            }))

            results = []

            for doc in documents:
                event_data = {
                    "_id": str(doc.get("_id")),
                    "event_id": doc.get("event_id"),
                    "event_name": doc.get("event_name"),
                    "assigned_to": doc.get("assigned_to", []),
                    "levels": []
                }

                for level in doc.get("levels", []):
                    level_data = {
                        "level_id": level.get("level_id"),
                        "level_name": level.get("level_name"),
                        "total_points": level.get("total_points"),
                        "tasks": []
                    }

                    for task in level.get("tasks", []):
                        task_data = {
                            "task_id": task.get("task_id"),
                            "task_name": task.get("task_name"),
                            "description": task.get("description"),
                            "total_points": task.get("total_points"),
                            "deadline": task.get("deadline"),
                            "marking_criteria": task.get("marking_criteria", {}),
                            "subtasks": []
                        }

                        for subtask in task.get("subtasks", []):
                            subtask_data = {
                                "subtask_id": subtask.get("subtask_id"),
                                "name": subtask.get("name"),
                                "description": subtask.get("description"),
                                "points": subtask.get("points"),
                                "deadline": subtask.get("deadline"),
                                "status": subtask.get("status")
                            }
                            task_data["subtasks"].append(subtask_data)

                        level_data["tasks"].append(task_data)

                    event_data["levels"].append(level_data)

                results.append(event_data)

            return JsonResponse({"events": results}, status=200)

        except Exception as e:
            print("❌ Error:", str(e))
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)  

@csrf_exempt
def get_admin_events(request):
    """
    Returns all events where the logged-in admin is assigned.
    For each event, only the admin's info is returned from assigned_to,
    along with the full levels and their tasks.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        # ✅ Extract token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({"error": "Authorization header missing or invalid"}, status=401)

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        admin_id = decoded.get("admin_id")
        print(f"Decoded admin_id: {admin_id}")

        if not admin_id:
            return JsonResponse({"error": "Invalid token payload"}, status=400)

        print("📩 Admin ID:", admin_id)

        # ✅ Find all events where this admin is in assigned_to
        events_cursor = tasks_collection.find({
            "assigned_to.admin_id": str(admin_id)
        })

        events = []
        for event in events_cursor:
            event['_id'] = str(event['_id'])  # Convert ObjectId
            event['created_at'] = str(event.get('created_at'))
            event['updated_at'] = str(event.get('updated_at'))

            # Filter only the logged-in admin from assigned_to
            event['assigned_to'] = [
                admin for admin in event.get('assigned_to', [])
                if admin.get('admin_id') == str(admin_id)
            ]

            events.append(event)

        if not events:
            return JsonResponse({"message": "No events found for this admin."}, status=404)

        return JsonResponse({
            "message": f"Found {len(events)} events assigned to admin.",
            "events": events
        }, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "Invalid token"}, status=401)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)
    
@csrf_exempt
def get_event_task_by_admin(request, event_id):
    """
    Returns tasks and their subtasks for a specific event (by _id) assigned to the logged-in admin.
    For Daily/Weekly frequency tasks, returns frequency_based_marking_criteria instead of marking_criteria.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        # Step 1: Extract admin_id from JWT
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({"error": "Authorization header missing or invalid"}, status=401)

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        admin_id = decoded.get("admin_id")
        print("📩 Admin ID from token:", admin_id)
        print("📩 Event ID from request:", event_id)

        if not admin_id:
            return JsonResponse({"error": "Invalid token payload"}, status=400)

        # Step 2: Query by MongoDB _id, not event_id
        event_docs = list(tasks_collection.find({
            "_id": ObjectId(event_id),
            "assigned_to": {"$elemMatch": {"admin_id": str(admin_id)}}
        }))
        print("📩 Event documents found:", event_docs)

        if not event_docs:
            print(f"No event found with _id: {event_id} and admin_id: {admin_id}")
            return JsonResponse({"message": "Event not found or admin not assigned."}, status=404)

        # Process the event document
        result = []
        for doc in event_docs:
            event_name = doc.get("event_name", "Unknown Event")
            levels = doc.get("levels", [])
            for level in levels:
                level_id = level.get("level_id")
                level_name = level.get("level_name")
                for task in level.get("tasks", []):
                    task_frequency = task.get("frequency", "Once")
                    
                    # ✅ Choose marking criteria based on frequency
                    if task_frequency in ["Daily", "Weekly"]:
                        task_marking_criteria = task.get("frequency_based_marking_criteria", {})
                    else:
                        task_marking_criteria = task.get("marking_criteria", {})
                    
                    task_data = {
                        "task_id": task.get("task_id"),
                        "task_name": task.get("task_name"),
                        "description": task.get("description"),
                        "total_points": task.get("total_points"),
                        "deadline": task.get("deadline"),
                        "deadline_time": task.get("deadline_time"),
                        "full_deadline": task.get("full_deadline"),
                        "frequency": task_frequency,
                        "start_date": task.get("start_date"),
                        "end_date": task.get("end_date"),
                        "trigger_count": task.get("trigger_count", 1),  # ✅ Added trigger_count
                        "level_id": level_id,
                        "level_name": level_name,
                        "event_id": str(doc.get("_id")),
                        "event_name": event_name,
                        "marking_criteria": task_marking_criteria,  # ✅ Frequency-based criteria
                        "subtasks": []
                    }
                    
                    # ✅ Process subtasks with frequency-based marking criteria
                    for subtask in task.get("subtasks", []):
                        subtask_frequency = subtask.get("frequency", "Once")
                        
                        # Choose marking criteria based on subtask frequency
                        if subtask_frequency in ["Daily", "Weekly"]:
                            subtask_marking_criteria = subtask.get("frequency_based_marking_criteria", {})
                        else:
                            subtask_marking_criteria = subtask.get("marking_criteria", {})
                        
                        subtask_data = {
                            "subtask_id": subtask.get("subtask_id"),
                            "name": subtask.get("name"),
                            "description": subtask.get("description"),
                            "points": subtask.get("points"),
                            "deadline": subtask.get("deadline"),
                            "deadline_time": subtask.get("deadline_time"),
                            "full_deadline": subtask.get("full_deadline"),
                            "frequency": subtask_frequency,  # ✅ Added frequency
                            "trigger_count": subtask.get("trigger_count", 1),  # ✅ Added trigger_count
                            "status": subtask.get("status"),
                            "marking_criteria": subtask_marking_criteria  # ✅ Frequency-based criteria
                        }
                        task_data["subtasks"].append(subtask_data)
                    
                    result.append(task_data)

        if not result:
            return JsonResponse({"message": "No tasks found in this event."}, status=404)

        return JsonResponse({
            "message": f"Found {len(result)} tasks for event {event_id}.",
            "tasks": result
        }, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "Invalid token"}, status=401)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def get_task_by_event_task_id(request, event_id, task_id):
    """
    Returns a specific task by event_id and task_id for the logged-in admin.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        # Step 1: Extract admin_id from JWT
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({"error": "Authorization header missing or invalid"}, status=401)

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        admin_id = decoded.get("admin_id")

        if not admin_id:
            return JsonResponse({"error": "Invalid token payload"}, status=400)

        # Step 2: Query event document
        event_doc = tasks_collection.find_one({
            "event_id": str(event_id),
            "assigned_to": {"$elemMatch": {"admin_id": str(admin_id)}}
        })

        if not event_doc:
            return JsonResponse({"error": "Event not found or admin not assigned"}, status=404)

        # Step 3: Find the specific task
        task_data = None
        for level in event_doc.get("levels", []):
            for task in level.get("tasks", []):
                if task.get("task_id") == str(task_id):
                    task_data = {
                        "task_id": task.get("task_id"),
                        "task_name": task.get("task_name"),
                        "description": task.get("description"),
                        "total_points": task.get("total_points"),
                        "deadline": task.get("deadline"),
                        "level_id": level.get("level_id"),
                        "level_name": level.get("level_name"),
                        "event_id": event_doc.get("event_id"),
                        "event_name": event_doc.get("event_name"),
                        "marking_criteria": task.get("marking_criteria", {}),  # Added marking_criteria
                        "subtasks": [
                            {
                                "subtask_id": subtask.get("subtask_id"),
                                "name": subtask.get("name"),
                                "description": subtask.get("description"),
                                "points": subtask.get("points"),
                                "deadline": subtask.get("deadline"),
                                "status": subtask.get("status"),
                                "marking_criteria": subtask.get("marking_criteria", {})
                            } for subtask in task.get("subtasks", [])
                        ]
                    }
                    break
            if task_data:
                break

        if not task_data:
            return JsonResponse({"error": "Task not found"}, status=404)

        return JsonResponse({
            "message": f"Task {task_id} found for event {event_id}.",
            "task": task_data
        }, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "Invalid token"}, status=401)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)
    
@csrf_exempt
def get_students_by_event_and_admin(request, event_id, admin_id):
    """
    GET: Return student details from users_collection for a given event_id and admin_id,
         based on emails listed in mapped_events_collection.assigned_admins.users.
    """
    if request.method != "GET":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        # Step 1: Get the mapped event document
        mapped_doc = mapped_events_collection.find_one({"event_id": str(event_id)})
        if not mapped_doc:
            return JsonResponse({"error": "Event not found"}, status=404)

        # Step 2: Find the correct admin entry
        admin_entry = next(
            (admin for admin in mapped_doc.get("assigned_admins", []) if admin["admin_id"] == admin_id),
            None
        )
        if not admin_entry:
            return JsonResponse({"error": f"Admin {admin_id} not assigned to this event."}, status=404)

        # Step 3: Extract emails
        emails = [user["email"] for user in admin_entry.get("users", []) if "email" in user]

        if not emails:
            return JsonResponse({"message": "No student emails found under this admin."}, status=200)

        # Step 4: Query User collection for matching students
        students_cursor = users_collection.find({"email": {"$in": emails}})
        students = []
        for student in students_cursor:
            student["_id"] = str(student["_id"])  # Convert ObjectId to string
            students.append(student)

        return JsonResponse({
            "message": f"{len(students)} students found for event {event_id} and admin {admin_id}.",
            "students": students
        }, status=200)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)
    
# @csrf_exempt
# def manage_task_points(request, event_id, task_id):
#     """
#     GET: Retrieve points for students in a specific task for the logged-in admin.
#     POST: Store student points inside the assigned_to → marks of the specific admin.
#     Supports Once, Daily, and Weekly frequencies with completion_history tracking.
#     """
#     try:
#         # ✅ Extract admin ID from JWT token
#         auth_header = request.headers.get('Authorization')
#         if not auth_header or not auth_header.startswith('Bearer '):
#             return JsonResponse({"error": "Authorization header missing or invalid"}, status=401)

#         token = auth_header.split(' ')[1]
#         decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
#         admin_id = decoded.get("admin_id")
#         admin_name = decoded.get("name", "Unknown Admin")
#         print("📩 Admin ID from token:", admin_name)    
#         now_timestamp = datetime.utcnow()
#         today_date = now_timestamp.strftime("%Y-%m-%d")

#         if not admin_id:
#             return JsonResponse({"error": "Invalid token payload"}, status=400)

#     except jwt.ExpiredSignatureError:
#         return JsonResponse({"error": "Token expired"}, status=401)
#     except jwt.InvalidTokenError:
#         return JsonResponse({"error": "Invalid token"}, status=401)
#     except Exception as e:
#         return JsonResponse({"error": f"Token error: {str(e)}"}, status=500)

#     if request.method == "GET":
#         try:
#             # ✅ Get ALL students assigned to this admin for this event
#             mapped_doc = mapped_events_collection.find_one({"event_id": str(event_id)})
#             all_students = []
            
#             if mapped_doc:
#                 admin_entry_mapped = next(
#                     (admin for admin in mapped_doc.get("assigned_admins", []) 
#                      if admin.get("admin_id") == admin_id),
#                     None
#                 )
                
#                 if admin_entry_mapped:
#                     student_emails = [user.get("email") for user in admin_entry_mapped.get("users", []) 
#                                     if "email" in user]
                    
#                     if student_emails:
#                         students_cursor = users_collection.find({"email": {"$in": student_emails}})
#                         for student in students_cursor:
#                             all_students.append({
#                                 "email": student.get("email"),
#                                 "name": student.get("name"),
#                                 "roll_no": student.get("student_id"),
#                                 "department": student.get("department")
#                             })

#             # ✅ Get the task details from tasks collection to find all subtasks
#             event_doc_task = tasks_collection.find_one({"_id": ObjectId(event_id)})
#             subtasks_for_task = []
#             task_found = False

#             # ✅ Frequency map setup for levels + subtasks extraction
#             level_frequency_map = {}
#             if event_doc_task:
#                 for level in event_doc_task.get("levels", []):
#                     level_id_inner = level.get("level_id")
#                     frequency = None
                    
#                     # Get frequency from ANY task in this level
#                     for task in level.get("tasks", []):
#                         if task.get("frequency"):
#                             frequency = task.get("frequency")
#                             break  # Use the first frequency found in this level

#                     # Check if this level contains our target task
#                     for task in level.get("tasks", []):
#                         if task.get("task_id") == task_id:
#                             subtasks_for_task = task.get("subtasks", [])
#                             task_found = True
#                             break

#                     if level_id_inner:
#                         level_frequency_map[level_id_inner] = frequency

#             # ✅ Get existing points data
#             task_points = []
#             event_doc = points_collection.find_one({"event_id": str(event_id)})
            
#             # ✅ Enhanced frequency handling for GET
#             if subtasks_for_task:
#                 # Handle tasks with subtasks
#                 for subtask in subtasks_for_task:
#                     subtask_id = subtask.get("subtask_id")
#                     subtask_frequency = subtask.get("frequency", "Once")
#                     trigger_count = subtask.get("trigger_count", 1)
                    
#                     for student in all_students:
#                         student_email = student.get("email")
#                         student_status = "incomplete"
#                         student_points = 0
#                         completion_history = []
                        
#                         if event_doc:
#                             admin_entry = next(
#                                 (a for a in event_doc.get("assigned_to", []) if a.get("admin_id") == admin_id),
#                                 None
#                             )
                            
#                             if admin_entry:
#                                 for student_mark in admin_entry.get("marks", []):
#                                     if student_mark.get("student_email") == student_email:
#                                         for level in student_mark.get("score", []):
#                                             for task in level.get("task", []):
#                                                 if task.get("task_id") == task_id:
#                                                     for sub_task in task.get("sub_task", []):
#                                                         if sub_task.get("subtask_id") == subtask_id:
#                                                             if subtask_frequency == "Once":
#                                                                 # Legacy single point system
#                                                                 student_status = sub_task.get("status", "incomplete")
#                                                                 student_points = sub_task.get("points", 0)
#                                                             else:
#                                                                 # New completion_history system
#                                                                 completion_history = sub_task.get("completion_history", [])
#                                                                 student_points = sum(entry.get("points", 0) for entry in completion_history)
#                                                                 # Determine overall status based on completion history
#                                                                 if len(completion_history) == trigger_count:
#                                                                     student_status = "completed"
#                                                                 elif len(completion_history) > 0:
#                                                                     student_status = "partially_completed"
#                                                                 else:
#                                                                     student_status = "incomplete"
#                                                             break
                        
#                         task_points.append({
#                             "roll_no": student.get("roll_no", student_email.split("@")[0]),
#                             "student_name": student.get("name"),
#                             "student_email": student_email,
#                             "points": student_points,
#                             "status": student_status,
#                             "subtask_id": subtask_id,
#                             "subtask_name": subtask.get("name", ""),
#                             "frequency": subtask_frequency,
#                             "trigger_count": trigger_count,
#                             "completion_history": completion_history,
#                             "time": None,
#                             "updated_time": None
#                         })
                        
#                         print(f"Added point entry: roll_no={student.get('roll_no', student_email.split('@')[0])}, status={student_status}, subtask_id={subtask_id}, frequency={subtask_frequency}")
            
#             else:
#                 # Handle tasks without subtasks
#                 for student in all_students:
#                     student_email = student.get("email")
#                     student_status = "incomplete"
#                     student_points = 0
#                     completion_history = []
                    
#                     # Find the task to get its frequency
#                     task_frequency = "Once"
#                     task_trigger_count = 1
#                     if event_doc_task:
#                         for level in event_doc_task.get("levels", []):
#                             for task in level.get("tasks", []):
#                                 if task.get("task_id") == task_id:
#                                     task_frequency = task.get("frequency", "Once")
#                                     task_trigger_count = task.get("trigger_count", 1)
#                                     break
                    
#                     if event_doc:
#                         admin_entry = next(
#                             (a for a in event_doc.get("assigned_to", []) if a.get("admin_id") == admin_id),
#                             None
#                         )
                        
#                         if admin_entry:
#                             for student_mark in admin_entry.get("marks", []):
#                                 if student_mark.get("student_email") == student_email:
#                                     for level in student_mark.get("score", []):
#                                         for task in level.get("task", []):
#                                             if task.get("task_id") == task_id and not task.get("sub_task"):
#                                                 if task_frequency == "Once":
#                                                     # Legacy single point system
#                                                     student_status = task.get("status", "incomplete")
#                                                     student_points = task.get("points", 0)
#                                                 else:
#                                                     # New completion_history system
#                                                     completion_history = task.get("completion_history", [])
#                                                     student_points = sum(entry.get("points", 0) for entry in completion_history)
#                                                     # Determine overall status based on completion history
#                                                     if len(completion_history) == task_trigger_count:
#                                                         student_status = "completed"
#                                                     elif len(completion_history) > 0:
#                                                         student_status = "partially_completed"
#                                                     else:
#                                                         student_status = "incomplete"
#                                                 break
                    
#                     task_points.append({
#                         "roll_no": student.get("roll_no", student_email.split("@")[0]),
#                         "student_name": student.get("name"),
#                         "student_email": student_email,
#                         "points": student_points,
#                         "status": student_status,
#                         "subtask_id": None,
#                         "subtask_name": None,
#                         "frequency": task_frequency,
#                         "trigger_count": task_trigger_count,
#                         "completion_history": completion_history,
#                         "time": None,
#                         "updated_time": None
#                     })
                    
#                     print(f"Added point entry: roll_no={student.get('roll_no', student_email.split('@')[0])}, status={student_status}, task_id={task_id}, frequency={task_frequency}")

#             print(f"level_frequency: {level_frequency_map}")
#             return JsonResponse({"points": task_points, "level_frequency": level_frequency_map}, status=200)

#         except Exception as e:
#             import traceback
#             traceback.print_exc()
#             return JsonResponse({"error": str(e)}, status=500)

#     elif request.method == "POST":
#         try:
#             data = json.loads(request.body)

#             # Extract common fields
#             event_id = str(data.get("event_id"))
#             event_name = data.get("event_name", "")
#             level_id = data.get("level_id")
#             level_name = data.get("level_name", "")
#             task_id = data.get("task_id")
#             task_name = data.get("task_name", "")
#             subtask_id = data.get("subtask_id")
#             subtask_name = data.get("subtask_name", "")
#             students = data.get("students", [])
            
#             # ✅ New fields for frequency handling
#             frequency = data.get("frequency", "Once")
#             current_date = data.get("current_date", today_date)  # Allow frontend to specify date

#             # Validate required fields
#             if not all([event_id, task_id, students]):
#                 return JsonResponse({"error": "Missing required fields"}, status=400)

#             # Check if task has subtasks
#             event_doc_task = tasks_collection.find_one({"_id": ObjectId(event_id)})
#             subtasks_for_task = []
#             task_found = False

#             # ✅ Frequency map setup for levels + subtasks extraction
#             level_frequency_map = {}
#             if event_doc_task:
#                 print(f"🔍 POST: Building frequency map for event_id: {event_id}")
#                 for level in event_doc_task.get("levels", []):
#                     level_id_inner = level.get("level_id")
#                     frequency_inner = None
#                     print(f"🔍 POST: Processing level_id: {level_id_inner}")
                    
#                     # Get frequency from ANY task in this level
#                     for task in level.get("tasks", []):
#                         if task.get("frequency"):
#                             frequency_inner = task.get("frequency")
#                             print(f"🔍 POST: Found frequency: {frequency_inner} for level: {level_id_inner}")
#                             break  # Use the first frequency found in this level

#                     # Store frequency in map
#                     if level_id_inner:
#                         level_frequency_map[level_id_inner] = frequency_inner

#                     # Check if this level contains our target task
#                     for task in level.get("tasks", []):
#                         if task.get("task_id") == task_id:
#                             subtasks_for_task = task.get("subtasks", [])
#                             task_found = True
#                             print(f"🔍 POST: Found target task_id: {task_id} in level: {level_id_inner}")
#                             break

#             # Determine if this is a task with subtasks or without
#             has_subtasks = len(subtasks_for_task) > 0
            
#             # Handle subtask_id validation and adjustment
#             if has_subtasks:
#                 # For tasks with subtasks, validate that subtask_id exists
#                 if not subtask_id or subtask_id not in [st.get("subtask_id") for st in subtasks_for_task]:
#                     return JsonResponse({"error": "Invalid or missing subtask_id for task with subtasks"}, status=400)
#             else:
#                 # For tasks without subtasks, subtask_id might be the task_id (from frontend)
#                 # We set it to None to indicate direct task management
#                 if subtask_id == task_id:
#                     subtask_id = None
#                     subtask_name = ""
#                 elif subtask_id is not None:
#                     return JsonResponse({"error": "subtask_id provided for task without subtasks"}, status=400)

#             # Fetch or create event doc
#             event_doc = points_collection.find_one({"event_id": event_id})
#             if not event_doc:
#                 points_collection.insert_one({
#                     "event_id": event_id,
#                     "event_name": event_name,
#                     "assigned_to": [{
#                         "admin_id": admin_id,
#                         "name": admin_name,
#                         "marks": []
#                     }]
#                 })
#                 event_doc = points_collection.find_one({"event_id": event_id})

#             updated = False

#             # Find or create admin entry
#             admin_entry = next(
#                 (a for a in event_doc.get("assigned_to", []) if a["admin_id"] == admin_id),
#                 None
#             )
#             if not admin_entry:
#                 admin_entry = {
#                     "admin_id": admin_id,
#                     "name": admin_name,
#                     "marks": []
#                 }
#                 event_doc.setdefault("assigned_to", []).append(admin_entry)
#                 updated = True

#             # Add or update marks for each student
#             for student in students:
#                 student_email = student.get("student_email")
#                 student_name = student.get("student_name")
#                 points = student.get("points", 0)
#                 status = student.get("status", "incomplete")

#                 if not student_email:
#                     continue

#                 print(f"Processing student: {student_email}, status: {status}, points: {points}, frequency: {frequency}")

#                 student_found = False
#                 for s in admin_entry.get("marks", []):
#                     if s["student_email"] == student_email:
#                         student_found = True
                        
#                         # ✅ FIRST: Update frequency for ALL existing levels for this student
#                         for level in s.get("score", []):
#                             existing_level_id = level.get("level_id")
#                             expected_frequency = level_frequency_map.get(existing_level_id)
#                             current_frequency = level.get("frequency")
                            
#                             if current_frequency != expected_frequency:
#                                 level["frequency"] = expected_frequency
#                                 print(f"🔁 Updated frequency for existing level {existing_level_id}: {current_frequency} -> {expected_frequency}")
#                                 updated = True
#                             elif "frequency" not in level and expected_frequency is not None:
#                                 level["frequency"] = expected_frequency
#                                 print(f"🆕 Added missing frequency for level {existing_level_id} -> {expected_frequency}")
#                                 updated = True
                        
#                         # ✅ SECOND: Process the specific level for the current task
#                         level_found = False
#                         for level in s.get("score", []):
#                             if level["level_id"] == level_id:
#                                 print(f"Found existing level_id={level_id} for student {student_email}")
#                                 level_found = True
#                                 task_found = False
                                
#                                 for task in level.get("task", []):
#                                     if task["task_id"] == task_id:
#                                         task_found = True
                                        
#                                         if subtask_id and subtasks_for_task:
#                                             # Handle subtask with frequency
#                                             subtask_found = False
#                                             for sub in task.get("sub_task", []):
#                                                 if sub["subtask_id"] == subtask_id:
#                                                     subtask_found = True
                                                    
#                                                     if frequency == "Once":
#                                                         # Current logic for Once frequency
#                                                         old_points = sub.get("points", 0)
#                                                         old_status = sub.get("status", "incomplete")
#                                                         old_name = sub.get("subtask_name", "")
                                                        
#                                                         if (old_points != points or 
#                                                             old_status != status or 
#                                                             old_name != subtask_name):
#                                                             sub["points"] = points
#                                                             sub["subtask_name"] = subtask_name
#                                                             sub["status"] = status
#                                                             sub["last_updated_on"] = now_timestamp
#                                                             if "points_assigned_on" not in sub:
#                                                                 sub["points_assigned_on"] = now_timestamp
#                                                             updated = True
#                                                     else:
#                                                         # Weekly or Daily frequency - use completion_history
#                                                         completion_history = sub.setdefault("completion_history", [])
                                                        
#                                                         # Check if entry for current_date already exists
#                                                         existing_entry = next((entry for entry in completion_history 
#                                                                               if entry.get("date") == current_date), None)
                                                        
#                                                         if not existing_entry:
#                                                             # Add new entry for current date
#                                                             completion_history.append({
#                                                                 "date": current_date,
#                                                                 "status": status,
#                                                                 "points": points,
#                                                                 "timestamp": now_timestamp
#                                                             })
#                                                             # Update subtask metadata
#                                                             sub["subtask_name"] = subtask_name
#                                                             sub["last_updated_on"] = now_timestamp
#                                                             if "points_assigned_on" not in sub:
#                                                                 sub["points_assigned_on"] = now_timestamp
#                                                             updated = True
#                                                             print(f"✅ Added {frequency} entry for {current_date}")
#                                                         else:
#                                                             # Update existing entry for current date
#                                                             if (existing_entry.get("points") != points or 
#                                                                 existing_entry.get("status") != status):
#                                                                 existing_entry["points"] = points
#                                                                 existing_entry["status"] = status
#                                                                 existing_entry["timestamp"] = now_timestamp
#                                                                 sub["last_updated_on"] = now_timestamp
#                                                                 updated = True
#                                                                 print(f"🔄 Updated {frequency} entry for {current_date}")
#                                                             else:
#                                                                 print(f"⚠️ Entry for {current_date} already exists with same data")
#                                                     break
                                            
#                                             if not subtask_found:
#                                                 # Create new subtask
#                                                 new_subtask = {
#                                                     "subtask_id": subtask_id,
#                                                     "subtask_name": subtask_name,
#                                                     "frequency": frequency,
#                                                     "points_assigned_on": now_timestamp,
#                                                     "last_updated_on": now_timestamp
#                                                 }
                                                
#                                                 if frequency == "Once":
#                                                     new_subtask.update({
#                                                         "points": points,
#                                                         "status": status
#                                                     })
#                                                 else:
#                                                     new_subtask["completion_history"] = [{
#                                                         "date": current_date,
#                                                         "status": status,
#                                                         "points": points,
#                                                         "timestamp": now_timestamp
#                                                     }]
                                                
#                                                 task["sub_task"].append(new_subtask)
#                                                 updated = True
#                                                 print(f"Added new subtask for {student_email}")
                                            
#                                             # Recalculate total task points for subtasks
#                                             if frequency == "Once":
#                                                 task["points"] = sum(st.get("points", 0) for st in task.get("sub_task", []))
#                                             else:
#                                                 # Sum all completion history points
#                                                 total_points = 0
#                                                 for st in task.get("sub_task", []):
#                                                     if st.get("completion_history"):
#                                                         total_points += sum(entry.get("points", 0) for entry in st["completion_history"])
#                                                     else:
#                                                         total_points += st.get("points", 0)
#                                                 task["points"] = total_points
                                        
#                                         else:
#                                             # Handle task without subtasks with frequency
#                                             if frequency == "Once":
#                                                 # Current logic for Once frequency
#                                                 old_points = task.get("points", 0)
#                                                 old_status = task.get("status", "incomplete")
                                                
#                                                 if old_points != points or old_status != status:
#                                                     task["points"] = points
#                                                     task["status"] = status
#                                                     task["last_updated_on"] = now_timestamp
#                                                     if "points_assigned_on" not in task:
#                                                         task["points_assigned_on"] = now_timestamp
#                                                     task["sub_task"] = []
#                                                     updated = True
                                            
#                                             else:
#                                                 # Weekly or Daily frequency - use completion_history
#                                                 completion_history = task.setdefault("completion_history", [])
                                                
#                                                 # Check if entry for current_date already exists
#                                                 existing_entry = next((entry for entry in completion_history 
#                                                                       if entry.get("date") == current_date), None)
                                                
#                                                 if not existing_entry:
#                                                     # Add new entry for current date
#                                                     completion_history.append({
#                                                         "date": current_date,
#                                                         "status": status,
#                                                         "points": points,
#                                                         "timestamp": now_timestamp
#                                                     })
#                                                     task["last_updated_on"] = now_timestamp
#                                                     if "points_assigned_on" not in task:
#                                                         task["points_assigned_on"] = now_timestamp
#                                                     updated = True
#                                                     print(f"✅ Added {frequency} task entry for {current_date}")
#                                                 else:
#                                                     # Update existing entry for current date
#                                                     if (existing_entry.get("points") != points or 
#                                                         existing_entry.get("status") != status):
#                                                         existing_entry["points"] = points
#                                                         existing_entry["status"] = status
#                                                         existing_entry["timestamp"] = now_timestamp
#                                                         task["last_updated_on"] = now_timestamp
#                                                         updated = True
#                                                         print(f"🔄 Updated {frequency} task entry for {current_date}")
#                                                     else:
#                                                         print(f"⚠️ Task entry for {current_date} already exists with same data")
                                                
#                                                 # Recalculate total task points
#                                                 task["points"] = sum(entry.get("points", 0) for entry in completion_history)
#                                         break
                                
#                                 if not task_found:
#                                     # Create new task with frequency support
#                                     task_data = {
#                                         "task_id": task_id,
#                                         "task_name": task_name,
#                                         "frequency": frequency,
#                                         "points_assigned_on": now_timestamp,
#                                         "last_updated_on": now_timestamp,
#                                         "sub_task": []
#                                     }
                                    
#                                     if subtask_id and subtasks_for_task:
#                                         # Task with subtasks
#                                         subtask_data = {
#                                             "subtask_id": subtask_id,
#                                             "subtask_name": subtask_name,
#                                             "frequency": frequency,
#                                             "points_assigned_on": now_timestamp,
#                                             "last_updated_on": now_timestamp
#                                         }
                                        
#                                         if frequency == "Once":
#                                             subtask_data.update({
#                                                 "points": points,
#                                                 "status": status
#                                             })
#                                             task_data["points"] = points
#                                         else:
#                                             subtask_data["completion_history"] = [{
#                                                 "date": current_date,
#                                                 "status": status,
#                                                 "points": points,
#                                                 "timestamp": now_timestamp
#                                             }]
#                                             task_data["points"] = points
                                        
#                                         task_data["sub_task"] = [subtask_data]
                                    
#                                     elif frequency != "Once":
#                                         # Task without subtasks but with frequency
#                                         task_data["completion_history"] = [{
#                                             "date": current_date,
#                                             "status": status,
#                                             "points": points,
#                                             "timestamp": now_timestamp
#                                         }]
#                                         task_data["points"] = points
                                    
#                                     else:
#                                         # Task without subtasks, Once frequency
#                                         task_data["status"] = status
#                                         task_data["points"] = points
                                    
#                                     level["task"].append(task_data)
#                                     updated = True
#                                 break
                        
#                         if not level_found:
#                             print(f"🆕 Creating new level for student {student_email}")
#                             print(f"🔍 Level ID: {level_id}")
#                             print(f"🔍 Frequency from map: {level_frequency_map.get(level_id)}")
#                             level_data = {
#                                 "level_id": level_id,
#                                 "level_name": level_name,
#                                 "frequency": level_frequency_map.get(level_id),  # ✅ Frequency from map
#                                 "task": [{
#                                     "task_id": task_id,
#                                     "task_name": task_name,
#                                     "frequency": frequency,
#                                     "points_assigned_on": now_timestamp,
#                                     "last_updated_on": now_timestamp,
#                                     "sub_task": []
#                                 }]
#                             }
                            
#                             if subtask_id and has_subtasks:
#                                 # Create level with subtask
#                                 subtask_data = {
#                                     "subtask_id": subtask_id,
#                                     "subtask_name": subtask_name,
#                                     "frequency": frequency,
#                                     "points_assigned_on": now_timestamp,
#                                     "last_updated_on": now_timestamp
#                                 }
                                
#                                 if frequency == "Once":
#                                     subtask_data.update({
#                                         "points": points,
#                                         "status": status
#                                     })
#                                     level_data["task"][0]["points"] = points
#                                 else:
#                                     subtask_data["completion_history"] = [{
#                                         "date": current_date,
#                                         "status": status,
#                                         "points": points,
#                                         "timestamp": now_timestamp
#                                     }]
#                                     level_data["task"][0]["points"] = points
                                
#                                 level_data["task"][0]["sub_task"] = [subtask_data]
                            
#                             elif frequency != "Once":
#                                 # Task without subtasks but with frequency
#                                 level_data["task"][0]["completion_history"] = [{
#                                     "date": current_date,
#                                     "status": status,
#                                     "points": points,
#                                     "timestamp": now_timestamp
#                                 }]
#                                 level_data["task"][0]["points"] = points
                            
#                             else:
#                                 level_data["task"][0]["status"] = status
#                                 level_data["task"][0]["points"] = points
                            
#                             s["score"].append(level_data)
#                             updated = True
#                             print(f"Added new level for {student_email} with frequency: {level_frequency_map.get(level_id)}")
#                         break

#                 if not student_found:
#                     print(f"🆕 Creating new student {student_email}")
#                     print(f"🔍 Level ID: {level_id}")
#                     print(f"🔍 Frequency from map: {level_frequency_map.get(level_id)}")
#                     student_data = {
#                         "student_email": student_email,
#                         "student_name": student_name,
#                         "score": [{
#                             "level_id": level_id,
#                             "level_name": level_name,
#                             "frequency": level_frequency_map.get(level_id),  # ✅ Frequency from map
#                             "task": [{
#                                 "task_id": task_id,
#                                 "task_name": task_name,
#                                 "frequency": frequency,
#                                 "points_assigned_on": now_timestamp,
#                                 "last_updated_on": now_timestamp,
#                                 "sub_task": []
#                             }]
#                         }]
#                     }
                    
#                     if subtask_id and has_subtasks:
#                         # Create student with subtask
#                         subtask_data = {
#                             "subtask_id": subtask_id,
#                             "subtask_name": subtask_name,
#                             "frequency": frequency,
#                             "points_assigned_on": now_timestamp,
#                             "last_updated_on": now_timestamp
#                         }
                        
#                         if frequency == "Once":
#                             subtask_data.update({
#                                 "points": points,
#                                 "status": status
#                             })
#                             student_data["score"][0]["task"][0]["points"] = points
#                         else:
#                             subtask_data["completion_history"] = [{
#                                 "date": current_date,
#                                 "status": status,
#                                 "points": points,
#                                 "timestamp": now_timestamp
#                             }]
#                             student_data["score"][0]["task"][0]["points"] = points
                        
#                         student_data["score"][0]["task"][0]["sub_task"] = [subtask_data]
                    
#                     elif frequency != "Once":
#                         # Task without subtasks but with frequency
#                         student_data["score"][0]["task"][0]["completion_history"] = [{
#                             "date": current_date,
#                             "status": status,
#                             "points": points,
#                             "timestamp": now_timestamp
#                         }]
#                         student_data["score"][0]["task"][0]["points"] = points
                    
#                     else:
#                         student_data["score"][0]["task"][0]["status"] = status
#                         student_data["score"][0]["task"][0]["points"] = points
                    
#                     admin_entry.setdefault("marks", []).append(student_data)
#                     updated = True
#                     print(f"Added new student {student_email} with level frequency: {level_frequency_map.get(level_id)}")

#             print(f"Updated flag: {updated}")
            
#             if updated:
#                 # Add debugging before database update
#                 print("🔍 DEBUG: About to update database with event_doc structure:")
#                 for assigned_admin in event_doc.get("assigned_to", []):
#                     if assigned_admin.get("admin_id") == admin_id:
#                         for mark in assigned_admin.get("marks", []):
#                             for score in mark.get("score", []):
#                                 print(f"🔍 Level {score.get('level_id')}: frequency = {score.get('frequency')}")
                
#                 result = points_collection.replace_one({"_id": event_doc["_id"]}, event_doc)
#                 print(f"Database update result: {result.modified_count} documents modified")
                
#                 # Add debugging after database update to verify
#                 updated_doc = points_collection.find_one({"_id": event_doc["_id"]})
#                 print("🔍 DEBUG: After database update, verifying frequency in DB:")
#                 for assigned_admin in updated_doc.get("assigned_to", []):
#                     if assigned_admin.get("admin_id") == admin_id:
#                         for mark in assigned_admin.get("marks", []):
#                             for score in mark.get("score", []):
#                                 print(f"🔍 DB Level {score.get('level_id')}: frequency = {score.get('frequency')}")

#             return JsonResponse({
#                 "message": "Points updated successfully" if updated else "No changes made",
#                 "updated": updated,
#                 "students_processed": len(students),
#                 "frequency": frequency,
#                 "current_date": current_date
#             }, status=200)

#         except Exception as e:
#             import traceback
#             traceback.print_exc()
#             return JsonResponse({"error": str(e)}, status=500)

#     else:
#         return JsonResponse({"error": "Invalid request method"}, status=405)
       

@csrf_exempt
def manage_task_points(request, event_id, task_id):
    """
    GET: Retrieve points for students in a specific task for the logged-in admin.
    POST: Store student points inside the assigned_to → marks of the specific admin.
    Also handles attendance tracking if enabled for the event.
    """
    try:
        # ✅ Extract admin ID from JWT token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({"error": "Authorization header missing or invalid"}, status=401)

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        admin_id = decoded.get("admin_id")
        admin_name = decoded.get("name", "Unknown Admin")
        print("📩 Admin ID from token:", admin_name)    
        now_timestamp = datetime.utcnow()  

        if not admin_id:
            return JsonResponse({"error": "Invalid token payload"}, status=400)

    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "Invalid token"}, status=401)
    except Exception as e:
        return JsonResponse({"error": f"Token error: {str(e)}"}, status=500)

    if request.method == "GET":
        try:
            # ✅ Get ALL students assigned to this admin for this event
            mapped_doc = mapped_events_collection.find_one({"event_id": str(event_id)})
            all_students = []
            attendance_required = False
            attendance_points = 0
            
            if mapped_doc:
                # Check if attendance tracking is enabled for this event
                event_details = tasks_collection.find_one({"_id": ObjectId(event_id)})
                if event_details:
                    attendance_tracking = event_details.get("attendance_tracking", {})
                    attendance_required = attendance_tracking.get("required", False)
                    attendance_points = attendance_tracking.get("points", 0)
                
                admin_entry_mapped = next(
                    (admin for admin in mapped_doc.get("assigned_admins", []) 
                     if admin.get("admin_id") == admin_id),
                    None
                )
                
                if admin_entry_mapped:
                    student_emails = [user.get("email") for user in admin_entry_mapped.get("users", []) 
                                    if "email" in user]
                    
                    if student_emails:
                        students_cursor = users_collection.find({"email": {"$in": student_emails}})
                        for student in students_cursor:
                            all_students.append({
                                "email": student.get("email"),
                                "name": student.get("name"),
                                "roll_no": student.get("student_id"),
                                "department": student.get("department")
                            })

            # ✅ Get the task details from tasks collection to find all subtasks
            event_doc_task = tasks_collection.find_one({"_id": ObjectId(event_id)})
            subtasks_for_task = []
            task_found = False
            current_task_frequency = "Once"  # Default frequency

            # ✅ Find the specific task and its frequency
            if event_doc_task:
                for level in event_doc_task.get("levels", []):
                    for task in level.get("tasks", []):
                        if task.get("task_id") == task_id:
                            subtasks_for_task = task.get("subtasks", [])
                            current_task_frequency = task.get("frequency", "Once")
                            task_found = True
                            break
                    if task_found:
                        break

            # ✅ Get existing points data and attendance data
            task_points = []
            event_doc = points_collection.find_one({"event_id": str(event_id)})
            
            if subtasks_for_task:
                # Handle tasks with subtasks
                for subtask in subtasks_for_task:
                    subtask_id = subtask.get("subtask_id")
                    
                    for student in all_students:
                        student_email = student.get("email")
                        student_status = "incomplete"
                        student_points = 0
                        attendance_info = {
                            "earned_points": 0,
                            "current_streak": 0,
                            "history": []
                        }
                        
                        if event_doc:
                            admin_entry = next(
                                (a for a in event_doc.get("assigned_to", []) if a.get("admin_id") == admin_id),
                                None
                            )
                            
                            if admin_entry:
                                for student_mark in admin_entry.get("marks", []):
                                    if student_mark.get("student_email") == student_email:
                                        # Get task points
                                        for level in student_mark.get("score", []):
                                            for task in level.get("task", []):
                                                if task.get("task_id") == task_id:
                                                    for sub_task in task.get("sub_task", []):
                                                        if sub_task.get("subtask_id") == subtask_id:
                                                            student_status = sub_task.get("status", "incomplete")
                                                            student_points = sub_task.get("points", 0)
                                                            break
                                        
                                        # Get attendance info
                                        if "attendance" in student_mark:
                                            attendance_info = {
                                                "earned_points": student_mark["attendance"].get("earned_points", 0),
                                                "current_streak": student_mark["attendance"].get("current_streak", 0),
                                                "history": student_mark["attendance"].get("history", [])
                                            }
                        
                        task_points.append({
                            "roll_no": student.get("roll_no", student_email.split("@")[0]),
                            "student_name": student.get("name"),
                            "student_email": student_email,
                            "points": student_points,
                            "status": student_status,
                            "subtask_id": subtask_id,
                            "subtask_name": subtask.get("name", ""),
                            "time": None,
                            "updated_time": None,
                            "attendance": {
                                "required": attendance_required,
                                "total_points": attendance_points,
                                "earned_points": attendance_info["earned_points"],
                                "current_streak": attendance_info["current_streak"],
                                "history": attendance_info["history"]
                            }
                        })
            else:
                # Handle tasks without subtasks
                for student in all_students:
                    student_email = student.get("email")
                    student_status = "incomplete"
                    student_points = 0
                    attendance_info = {
                        "earned_points": 0,
                        "current_streak": 0,
                        "history": []
                    }
                    
                    if event_doc:
                        admin_entry = next(
                            (a for a in event_doc.get("assigned_to", []) if a.get("admin_id") == admin_id),
                            None
                        )
                        
                        if admin_entry:
                            for student_mark in admin_entry.get("marks", []):
                                if student_mark.get("student_email") == student_email:
                                    # Get task points
                                    for level in student_mark.get("score", []):
                                        for task in level.get("task", []):
                                            if task.get("task_id") == task_id and not task.get("sub_task"):
                                                student_status = task.get("status", "incomplete")
                                                student_points = task.get("points", 0)
                                                break
                                    
                                    # Get attendance info
                                    if "attendance" in student_mark:
                                        attendance_info = {
                                            "earned_points": student_mark["attendance"].get("earned_points", 0),
                                            "current_streak": student_mark["attendance"].get("current_streak", 0),
                                            "history": student_mark["attendance"].get("history", [])
                                        }
                    
                    task_points.append({
                        "roll_no": student.get("roll_no", student_email.split("@")[0]),
                        "student_name": student.get("name"),
                        "student_email": student_email,
                        "points": student_points,
                        "status": student_status,
                        "subtask_id": None,
                        "subtask_name": None,
                        "time": None,
                        "updated_time": None,
                        "attendance": {
                            "required": attendance_required,
                            "total_points": attendance_points,
                            "earned_points": attendance_info["earned_points"],
                            "current_streak": attendance_info["current_streak"],
                            "history": attendance_info["history"]
                        }
                    })

            # Create task frequency map for the response
            task_frequency_map = {
                "task_id": task_id,
                "frequency": current_task_frequency
            }
            
            print(f"task_frequency: {current_task_frequency}")
            return JsonResponse({
                "points": task_points,
                "task_frequency": task_frequency_map,
                "attendance_tracking": {
                    "required": attendance_required,
                    "points": attendance_points
                }
            }, status=200)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return JsonResponse({"error": str(e)}, status=500)

    elif request.method == "POST":
        try:
            data = json.loads(request.body)

            # Extract common fields
            event_id = str(data.get("event_id"))
            event_name = data.get("event_name", "")
            level_id = data.get("level_id")
            level_name = data.get("level_name", "")
            task_id = data.get("task_id")
            task_name = data.get("task_name", "")
            subtask_id = data.get("subtask_id")
            subtask_name = data.get("subtask_name", "")
            students = data.get("students", [])
            
            # Validate required fields
            if not all([event_id, task_id, students]):
                return JsonResponse({"error": "Missing required fields"}, status=400)

            # Get event details to check for attendance tracking
            event_doc_task = tasks_collection.find_one({"_id": ObjectId(event_id)})
            if not event_doc_task:
                return JsonResponse({"error": "Event not found"}, status=404)
                
            # Check if attendance tracking is enabled
            attendance_tracking = event_doc_task.get("attendance_tracking", {})
            attendance_required = attendance_tracking.get("required", False)
            attendance_points = attendance_tracking.get("points", 0)
            
            # Automatically enable attendance marking if attendance tracking is required
            # But still respect the explicit mark_attendance setting from the client if provided
            attendance_data = data.get("attendance", {})
            mark_attendance = attendance_data.get("mark_attendance", attendance_required)
            
            # Use current date automatically instead of requiring it in the request
            record_date = datetime.now().strftime("%Y-%m-%d")


            # Validate required fields
            if not all([event_id, task_id, students]):
                return JsonResponse({"error": "Missing required fields"}, status=400)

            # Get event details to check for attendance tracking
            event_doc_task = tasks_collection.find_one({"_id": ObjectId(event_id)})
            if not event_doc_task:
                return JsonResponse({"error": "Event not found"}, status=404)
                
            # Check if attendance tracking is enabled
            attendance_tracking = event_doc_task.get("attendance_tracking", {})
            attendance_required = attendance_tracking.get("required", False)
            attendance_points = attendance_tracking.get("points", 0)
            
            # Automatically enable attendance marking if attendance tracking is required
            # But still respect the explicit mark_attendance setting from the client if provided
            attendance_data = data.get("attendance", {})
            mark_attendance = attendance_data.get("mark_attendance", attendance_required)
            
            # Use current date automatically instead of requiring it in the request
            now_dt = datetime.now()
            record_date = now_dt.strftime("%Y-%m-%d")
            
            # Find the specific task and its frequency
            event_frequency = "Once"  # Default
            event_start_date = None
            event_end_date = None
            total_days = 1
            current_task = None

            # First, find the specific task we're working with
            for level in event_doc_task.get("levels", []):
                for task in level.get("tasks", []):
                    if task.get("task_id") == task_id:
                        current_task = task
                        break
                if current_task:
                    break

            # If we found the task, use its frequency directly
            if current_task:
                event_frequency = current_task.get("frequency", "Once")
                print(f"📊 Found task '{task_name}' with frequency: {event_frequency}")
                if current_task.get("start_date"):
                    event_start_date = datetime.strptime(current_task.get("start_date"), "%Y-%m-%d").date()
                if current_task.get("end_date"):
                    event_end_date = datetime.strptime(current_task.get("end_date"), "%Y-%m-%d").date()
            else:
                print(f"⚠️ Task with ID '{task_id}' not found in event document")
                # Fallback to scanning all tasks if specific task not found
                for level in event_doc_task.get("levels", []):
                    for task in level.get("tasks", []):
                        if task.get("task_id") == task_id:
                            event_frequency = task.get("frequency", "Once")
                            if task.get("start_date"):
                                event_start_date = datetime.strptime(task.get("start_date"), "%Y-%m-%d").date()
                            if task.get("end_date"):
                                event_end_date = datetime.strptime(task.get("end_date"), "%Y-%m-%d").date()
                            break

            # Calculate total days
            if event_start_date and event_end_date:
                total_days = (event_end_date - event_start_date).days + 1
                print(f"📅 Task runs for {total_days} days from {event_start_date} to {event_end_date}")
            
            # Calculate points per attendance based on frequency
            points_per_attendance = calculate_points_per_attendance(attendance_points, event_frequency, total_days)
            print(f"💯 Points per attendance: {points_per_attendance} (based on {event_frequency} frequency)")

            # Check for subtasks
            subtasks_for_task = []
            task_found = False
            if current_task:
                subtasks_for_task = current_task.get("subtasks", [])
                task_found = True

            # Determine if this is a task with subtasks or without
            has_subtasks = len(subtasks_for_task) > 0
            
            # Handle subtask_id validation and adjustment
            if has_subtasks:
                # For tasks with subtasks, validate that subtask_id exists
                if not subtask_id or subtask_id not in [st.get("subtask_id") for st in subtasks_for_task]:
                    return JsonResponse({"error": "Invalid or missing subtask_id for task with subtasks"}, status=400)
            else:
                # For tasks without subtasks, subtask_id might be the task_id (from frontend)
                # We set it to None to indicate direct task management
                if subtask_id == task_id:
                    subtask_id = None
                    subtask_name = ""
                elif subtask_id is not None:
                    return JsonResponse({"error": "subtask_id provided for task without subtasks"}, status=400)

            # Fetch or create event doc
            event_doc = points_collection.find_one({"event_id": event_id})
            if not event_doc:
                points_collection.insert_one({
                    "event_id": event_id,
                    "event_name": event_name,
                    "assigned_to": [{
                        "admin_id": admin_id,
                        "name": admin_name,
                        "marks": []
                    }]
                })
                event_doc = points_collection.find_one({"event_id": event_id})

            updated = False
            attendance_updated = False

            # Find or create admin entry
            admin_entry = next(
                (a for a in event_doc.get("assigned_to", []) if a["admin_id"] == admin_id),
                None
            )
            if not admin_entry:
                admin_entry = {
                    "admin_id": admin_id,
                    "name": admin_name,
                    "marks": []
                }
                event_doc.setdefault("assigned_to", []).append(admin_entry)
                updated = True

            # Process students
            attendance_results = []
            for student in students:
                student_email = student.get("student_email")
                student_name = student.get("student_name")
                points = student.get("points", 0)
                status = student.get("status", "incomplete")
                # Automatically determine if student is present based on status
                # Consider "completed", "partially_finished", and "completely_finished" as present
                present = student.get("present", status in ["completed", "partially_finished", "completely_finished"])
                
                # Initialize attendance result for this student if needed
                if mark_attendance and attendance_required:
                    attendance_result = {
                        "student_email": student_email,
                        "present": present,
                        "points_earned": 0,
                        "current_streak": 0,
                        "updated": False
                    }
                    attendance_results.append(attendance_result)

                if not student_email:
                    continue

                print(f"Processing student: {student_email}, status: {status}, points: {points}")

                # Store reference to the current student record for attendance handling
                current_student_record = None
                
                student_found = False
                for s in admin_entry.get("marks", []):
                    if s["student_email"] == student_email:
                        current_student_record = s  # Store reference for later use
                        student_found = True
                        
                        # ✅ Process the specific level for the current task
                        level_found = False
                        for level in s.get("score", []):
                            if level["level_id"] == level_id:
                                print(f"Found existing level_id={level_id} for student {student_email}")
                                level_found = True
                                task_found = False
                                for task in level.get("task", []):
                                    if task["task_id"] == task_id:
                                        # Store task frequency directly in the task object
                                        if task.get("frequency") != event_frequency:
                                            task["frequency"] = event_frequency
                                            print(f"🔄 Updated frequency for task {task_id} to {event_frequency}")
                                            updated = True
                                        elif "frequency" not in task:
                                            task["frequency"] = event_frequency
                                            print(f"➕ Added frequency for task {task_id}: {event_frequency}")
                                            updated = True
                                            
                                        task_found = True
                                        if subtask_id and subtasks_for_task:
                                            # Handle subtask
                                            subtask_found = False
                                            for sub in task.get("sub_task", []):
                                                if sub["subtask_id"] == subtask_id:
                                                    subtask_found = True
                                                    old_points = sub.get("points", 0)
                                                    old_status = sub.get("status", "incomplete")
                                                    old_name = sub.get("subtask_name", "")
                                                    
                                                    print(f"Existing subtask data - points: {old_points}, status: {old_status}, name: {old_name}")
                                                    print(f"New subtask data - points: {points}, status: {status}, name: {subtask_name}")
                                                    
                                                    if (old_points != points or 
                                                        old_status != status or 
                                                        old_name != subtask_name):
                                                        sub["points"] = points
                                                        sub["subtask_name"] = subtask_name
                                                        sub["status"] = status
                                                        sub["last_updated_on"] = now_timestamp
                                                        if "points_assigned_on" not in sub:
                                                            sub["points_assigned_on"] = now_timestamp
                                                        updated = True
                                                        print(f"Updated subtask for {student_email}")

                                                    break
                                            
                                            if not subtask_found:
                                                task["sub_task"].append({
                                                "subtask_id": subtask_id,
                                                "subtask_name": subtask_name,
                                                "points": points,
                                                "status": status,
                                                "points_assigned_on": now_timestamp,
                                                "last_updated_on": now_timestamp
                                            })

                                                updated = True
                                                print(f"Added new subtask for {student_email}")
                                            
                                            task["points"] = sum(st["points"] for st in task.get("sub_task", []))
                                        else:
                                            # Handle task without subtasks
                                            old_points = task.get("points", 0)
                                            old_status = task.get("status", "incomplete")
                                            
                                            print(f"Existing task data - points: {old_points}, status: {old_status}")
                                            print(f"New task data - points: {points}, status: {status}")
                                            
                                            if old_points != points or old_status != status:
                                                task["points"] = points
                                                task["status"] = status
                                                task["last_updated_on"] = now_timestamp
                                                if "points_assigned_on" not in task:
                                                    task["points_assigned_on"] = now_timestamp
                                                task["sub_task"] = []  # Ensure no subtasks
                                                updated = True
                                                print(f"Updated task for {student_email}")
                                        break
                                
                                if not task_found:
                                    task_data = {
                                        "task_id": task_id,
                                        "task_name": task_name,
                                        "points": points,
                                        "frequency": event_frequency,  # Store frequency directly in task
                                        "sub_task": [],
                                        "points_assigned_on": now_timestamp,
                                        "last_updated_on": now_timestamp
                                    }
                                    if subtask_id and subtasks_for_task:
                                        task_data["sub_task"] = [{
                                            "subtask_id": subtask_id,
                                            "subtask_name": subtask_name,
                                            "points": points,
                                            "status": status,
                                            "points_assigned_on": now_timestamp,
                                            "last_updated_on": now_timestamp
                                        }]
                                        task_data["points"] = points
                                    else:
                                        task_data["status"] = status
                                    level["task"].append(task_data)
                                    updated = True
                                    print(f"Added new task for {student_email} with frequency: {event_frequency}")
                                break
                        
                        if not level_found:
                            print(f"🆕 Creating new level for student {student_email}")
                            print(f"🔍 Level ID: {level_id}")
                            level_data = {
                                "level_id": level_id,
                                "level_name": level_name,
                                "task": [{
                                    "task_id": task_id,
                                    "task_name": task_name,
                                    "frequency": event_frequency,  # Store frequency directly in task
                                    "points": points,
                                    "points_assigned_on": now_timestamp,
                                    "last_updated_on": now_timestamp,
                                    "sub_task": []
                                }]
                            }
                            if subtask_id and has_subtasks:
                                # Create level with subtask
                                level_data["task"][0]["sub_task"] = [{
                                    "subtask_id": subtask_id,
                                    "subtask_name": subtask_name,
                                    "points": points,
                                    "status": status,
                                    "points_assigned_on": now_timestamp,
                                    "last_updated_on": now_timestamp
                                }]
                                level_data["task"][0]["points"] = points
                            else:
                                level_data["task"][0]["status"] = status
                            s["score"].append(level_data)
                            updated = True
                            print(f"Added new level for {student_email} with task frequency: {event_frequency}")
                        break  # Break after finding the student

                # Handle attendance for existing students
                if student_found and mark_attendance and attendance_required and current_student_record:
                    # Initialize attendance if not exists
                    if "attendance" not in current_student_record:
                        current_student_record["attendance"] = {
                            "earned_points": 0,
                            "current_streak": 0,
                            "history": []
                        }
                    
                    # Get attendance history
                    history = current_student_record["attendance"].get("history", [])
                    
                    # Check if there's already a record for this date
                    existing_record_index = next(
                        (i for i, record in enumerate(history)
                        if record.get("date") == record_date),
                        None
                    )
                    
                    # Check if there's already a record for this specific task
                    task_record_index = next(
                        (i for i, record in enumerate(history)
                        if record.get("date") == record_date and record.get("task_id") == task_id),
                        None
                    )
                    
                    # Determine attendance handling based on frequency
                    if event_frequency == "Once":
                        # For "Once" tasks, only record attendance once per task
                        if task_record_index is None:
                            # No record for this task - create one
                            attendance_points_to_award = points_per_attendance if present else 0
                            attendance_record = {
                                "date": record_date,
                                "present": present,
                                "points": attendance_points_to_award,
                                "timestamp": now_dt,
                                "task_id": task_id
                            }
                            history.append(attendance_record)
                            
                            if present:
                                current_student_record["attendance"]["earned_points"] += attendance_points_to_award
                                for result in attendance_results:
                                    if result["student_email"] == student_email:
                                        result["points_earned"] = attendance_points_to_award
                                        break
                            
                            attendance_updated = True
                            print(f"Created new attendance record for 'Once' task {task_id} - Points: {attendance_points_to_award}")
                        
                    elif event_frequency == "Daily":
                        # For "Daily" tasks, check if we already have a record for today
                        if existing_record_index is not None:
                            # Already have a record for today - only update if from a different task
                            if task_record_index is None and present:
                                # This is a new task for today and student is present - add additional points
                                attendance_points_to_award = points_per_attendance
                                attendance_record = {
                                    "date": record_date,
                                    "present": present,
                                    "points": attendance_points_to_award,
                                    "timestamp": now_dt,
                                    "task_id": task_id
                                }
                                history.append(attendance_record)
                                
                                current_student_record["attendance"]["earned_points"] += attendance_points_to_award
                                for result in attendance_results:
                                    if result["student_email"] == student_email:
                                        result["points_earned"] = attendance_points_to_award
                                        break
                                
                                attendance_updated = True
                                print(f"Added additional attendance points for 'Daily' task {task_id} - Points: {attendance_points_to_award}")
                        else:
                            # No record for today - create one
                            attendance_points_to_award = points_per_attendance if present else 0
                            attendance_record = {
                                "date": record_date,
                                "present": present,
                                "points": attendance_points_to_award,
                                "timestamp": now_dt,
                                "task_id": task_id
                            }
                            history.append(attendance_record)
                            
                            if present:
                                current_student_record["attendance"]["earned_points"] += attendance_points_to_award
                                for result in attendance_results:
                                    if result["student_email"] == student_email:
                                        result["points_earned"] = attendance_points_to_award
                                        break
                            
                            attendance_updated = True
                            print(f"Created new attendance record for 'Daily' task {task_id} - Points: {attendance_points_to_award}")
                    
                    elif event_frequency == "Weekly":
                        # For "Weekly" tasks, determine the week number
                        current_week = now_dt.isocalendar()[1]
                        current_year = now_dt.year
                        
                        # Check if we have a record for this task this week
                        task_this_week = False
                        for record in history:
                            if record.get("task_id") == task_id:
                                try:
                                    record_date_obj = datetime.strptime(record.get("date"), "%Y-%m-%d")
                                    if (record_date_obj.isocalendar()[0] == current_year and 
                                        record_date_obj.isocalendar()[1] == current_week):
                                        task_this_week = True
                                        break
                                except (ValueError, TypeError):
                                    pass
                        
                        if not task_this_week:
                            # No record for this task this week - create one
                            attendance_points_to_award = points_per_attendance if present else 0
                            attendance_record = {
                                "date": record_date,
                                "present": present,
                                "points": attendance_points_to_award,
                                "timestamp": now_dt,
                                "task_id": task_id
                            }
                            history.append(attendance_record)
                            
                            if present:
                                current_student_record["attendance"]["earned_points"] += attendance_points_to_award
                                for result in attendance_results:
                                    if result["student_email"] == student_email:
                                        result["points_earned"] = attendance_points_to_award
                                        break
                            
                            attendance_updated = True
                            print(f"Created new attendance record for 'Weekly' task {task_id} - Points: {attendance_points_to_award}")
                    
                    # Recalculate streak if attendance was updated
                    if attendance_updated:
                        # Sort attendance records by date
                        history.sort(key=lambda x: datetime.strptime(x["date"], "%Y-%m-%d"))
                        
                        # Get all unique dates where the student was present
                        present_dates = set()
                        for record in history:
                            if record.get("present", False):
                                present_dates.add(record.get("date"))
                        
                        # Calculate streak based on consecutive dates
                        date_list = sorted(list(present_dates), reverse=True)
                        current_streak = 0
                        
                        if date_list:
                            current_date = datetime.strptime(date_list[0], "%Y-%m-%d")
                            for date_str in date_list:
                                date_obj = datetime.strptime(date_str, "%Y-%m-%d")
                                if (current_date - date_obj).days <= 1:
                                    current_streak += 1
                                    current_date = date_obj
                                else:
                                    break
                        
                        current_student_record["attendance"]["current_streak"] = current_streak
                        for result in attendance_results:
                            if result["student_email"] == student_email:
                                result["current_streak"] = current_streak
                                result["updated"] = True
                                break

                if not student_found:
                    print(f"🆕 Creating new student {student_email}")
                    print(f"🔍 Level ID: {level_id}")
                    student_data = {
                        "student_email": student_email,
                        "student_name": student_name,
                        "score": [{
                            "level_id": level_id,
                            "level_name": level_name,
                            "task": [{
                                "task_id": task_id,
                                "task_name": task_name,
                                "frequency": event_frequency,  # Store frequency directly in task
                                "points": points,
                                "points_assigned_on": now_timestamp,
                                "last_updated_on": now_timestamp,
                                "sub_task": []
                            }]
                        }]
                    }
                    
                    if subtask_id and has_subtasks:
                        # Create student with subtask
                        student_data["score"][0]["task"][0]["sub_task"] = [{
                            "subtask_id": subtask_id,
                            "subtask_name": subtask_name,
                            "points": points,
                            "status": status,
                            "points_assigned_on": now_timestamp,
                            "last_updated_on": now_timestamp
                        }]
                        student_data["score"][0]["task"][0]["points"] = points
                    else:
                        student_data["score"][0]["task"][0]["status"] = status
                        
                    # When adding attendance data for new students:
                    if mark_attendance and attendance_required:
                        # For a new student, always create the first attendance record
                        attendance_points_to_award = points_per_attendance if present else 0
                        
                        attendance_data = {
                            "earned_points": attendance_points_to_award,
                            "current_streak": 1 if present else 0,
                            "history": [{
                                "date": record_date,
                                "present": present,
                                "points": attendance_points_to_award,
                                "timestamp": now_dt,
                                "task_id": task_id  # Track which task created this record
                            }]
                        }
                        student_data["attendance"] = attendance_data
                        
                        for result in attendance_results:
                            if result["student_email"] == student_email:
                                result["points_earned"] = attendance_points_to_award
                                result["current_streak"] = 1 if present else 0
                                result["updated"] = True
                                break
                        
                        attendance_updated = True

                    admin_entry.setdefault("marks", []).append(student_data)
                    updated = True
                    print(f"Added new student {student_email} with task frequency: {event_frequency}")

            print(f"Updated flag: {updated}")
            print(f"Attendance updated flag: {attendance_updated}")
            
            if updated or attendance_updated:
                # Add debugging before database update
                print("🔍 DEBUG: About to update database with event_doc structure:")
                for assigned_admin in event_doc.get("assigned_to", []):
                    if assigned_admin.get("admin_id") == admin_id:
                        for mark in assigned_admin.get("marks", []):
                            for score in mark.get("score", []):
                                for task in score.get("task", []):
                                    print(f"🔍 Task {task.get('task_id')}: frequency = {task.get('frequency')}")
                
                result = points_collection.replace_one({"_id": event_doc["_id"]}, event_doc)
                print(f"Database update result: {result.modified_count} documents modified")
                
                # Add debugging after database update to verify
                updated_doc = points_collection.find_one({"_id": event_doc["_id"]})
                print("🔍 DEBUG: After database update, verifying frequency in DB:")
                for assigned_admin in updated_doc.get("assigned_to", []):
                    if assigned_admin.get("admin_id") == admin_id:
                        for mark in assigned_admin.get("marks", []):
                            for score in mark.get("score", []):
                                for task in score.get("task", []):
                                    print(f"🔍 DB Task {task.get('task_id')}: frequency = {task.get('frequency')}")

            response_data = {
                "message": "Data updated successfully" if updated or attendance_updated else "No changes made",
                "updated": updated or attendance_updated,
                "students_processed": len(students)
            }
            
            if mark_attendance and attendance_required:
                response_data["attendance"] = {
                    "updated": attendance_updated,
                    "results": attendance_results,
                    "points_per_attendance": points_per_attendance,
                    "event_frequency": event_frequency
                }
                
            return JsonResponse(response_data, status=200)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return JsonResponse({"error": str(e)}, status=500)

    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)

def calculate_points_per_attendance(total_points, frequency, total_days):
    """
    Calculate points to award per attendance based on frequency.
    
    Args:
        total_points (float): Total attendance points available for the event
        frequency (str): Task frequency ('Once', 'Daily', or 'Weekly')
        total_days (int): Total days the task runs for
        
    Returns:
        float: Points per attendance mark, rounded to 2 decimal places
    """
    if frequency == "Once":
        return total_points  # Award all points at once
    elif frequency == "Daily":
        # For daily tasks, divide total points by the number of days
        return round(total_points / max(1, total_days), 2)
    elif frequency == "Weekly":
        # For weekly tasks, divide total points by the number of weeks
        weeks = max(1, (total_days + 6) // 7)  # Ceiling division for weeks
        return round(total_points / weeks, 2)
    return total_points  # Default fallback
    
@csrf_exempt
def get_students_details(request, event_id):
    """
    GET: Return student details (email, name, roll_no, etc.) for given event_id and logged-in admin.
    """
    if request.method != "GET":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        # Step 1: Get JWT from headers
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JsonResponse({"error": "Authorization header missing or invalid"}, status=401)

        token = auth_header.split(" ")[1]
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        token_admin_id = decoded.get("admin_id")

        if not token_admin_id:
            return JsonResponse({"error": "admin_id missing from token"}, status=401)

        # Step 2: Get matching event with admin access
        event_doc = mapped_events_collection.find_one({"event_id": event_id})
        if not event_doc:
            return JsonResponse({"error": "Event not found"}, status=404)

        matched_admin = next((admin for admin in event_doc.get("assigned_admins", [])
                              if admin.get("admin_id") == token_admin_id), None)

        if not matched_admin:
            return JsonResponse({"error": "You are not assigned to this event"}, status=403)

        # Step 3: Get emails assigned to this admin
        user_emails = [user.get("email") for user in matched_admin.get("users", []) if "email" in user]

        if not user_emails:
            return JsonResponse({"students": []}, status=200)

        # Step 4: Fetch students from Students_Data where email matches
        student_docs = list(users_collection.find({"email": {"$in": user_emails}}))

        student_details = []
        for stu in student_docs:
            student_details.append({
                "_id": str(stu.get("_id")),
                "name": stu.get("name"),
                "student_id": stu.get("student_id"),
                "department": stu.get("department"),
                "email": stu.get("email")
            })

        return JsonResponse({"students": student_details}, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "Invalid token"}, status=401)
    except Exception as e:
        print("❌ Server error:", str(e))
        return JsonResponse({"error": "Internal server error"}, status=500)
    
@csrf_exempt
def leaderboard(request, event_id):
    """
    POST: Return leaderboard data for a specific event and admin.
    Shows student names, their points per level, and total points.
    Only the admin who submitted the data can access their students' scores.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method. Use POST."}, status=405)

    try:
        # Step 1: Get JWT from headers
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JsonResponse({"error": "Authorization header missing or invalid"}, status=401)

        token = auth_header.split(" ")[1]
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        token_admin_id = decoded.get("admin_id")

        if not token_admin_id:
            return JsonResponse({"error": "admin_id missing from token"}, status=401)

        # Step 2: Fetch the event points document
        points_doc = points_collection.find_one({"event_id": event_id})
        if not points_doc:
            return JsonResponse({"error": "Student not Assigned Yet or Points not Allocated "}, status=404)

        # Step 3: Find the admin's section
        admin_entry = next((a for a in points_doc.get("assigned_to", []) if a.get("admin_id") == token_admin_id), None)
        if not admin_entry:
            return JsonResponse({"error": "You are not assigned to this event"}, status=403)

        # Step 4: Build leaderboard for this admin's students
        leaderboard = []
        for student in admin_entry.get("marks", []):
            student_email = student.get("student_email")
            student_name = student.get("student_name", "Unknown Student")
            levels_points = []
            total_points = 0

            for level in student.get("score", []):
                level_id = level.get("level_id")
                level_name = level.get("level_name", "")
                level_points = sum(task.get("points", 0) for task in level.get("task", []))
                total_points += level_points

                levels_points.append({
                    "level_id": level_id,
                    "level_name": level_name,
                    "total_points": level_points
                })

            leaderboard.append({
                "student_name": student_name,
                "student_email": student_email,
                "levels": levels_points,
                "total_points": total_points  # ✅ Total score for student
            })

        if not leaderboard:
            return JsonResponse({"message": "No students found for this event."}, status=404)

        return JsonResponse({
            "message": f"Leaderboard for event {event_id} retrieved successfully.",
            "leaderboard": leaderboard
        }, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "Invalid token"}, status=401)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def forgot_password(request):
    """
    Handles forgot password requests by sending a reset link with a JWT token to the admin's email.
    Expects a POST request with JSON body containing 'email'.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get('email')

            if not email:
                logger.warning("Forgot password request missing email")
                return JsonResponse({'error': 'Email is required'}, status=400)

            # Check if admin exists
            admin_user = admin_collection.find_one({'email': email})
            if not admin_user:
                logger.warning(f"No account found for email: {email}")
                return JsonResponse({'error': 'No account found with this email'}, status=404)

            # Check if account is active
            if admin_user.get('status') != 'Active':
                logger.warning(f"Inactive account attempted password reset: {email}")
                return JsonResponse({'error': 'Account is inactive. Contact the administrator.'}, status=403)

            # Generate a JWT token
            expiry_time = timezone.now() + timedelta(minutes=30)
            payload = {
                'email': email,
                'exp': int(expiry_time.timestamp()),  # JWT expects Unix timestamp
                'iat': int(timezone.now().timestamp())  # Issued at time
            }
            reset_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            logger.info(f"Generated JWT token for {email}: {reset_token}")

            # Store the reset token and expiry in the admin document
            result = admin_collection.update_one(
                {'email': email},
                {
                    '$set': {
                        'reset_password_token': reset_token,
                        'reset_password_token_expiry': expiry_time
                    }
                }
            )

            if result.matched_count == 0:
                logger.error(f"No document matched for email: {email}")
                return JsonResponse({'error': 'Failed to update reset token: No matching document'}, status=500)
            if result.modified_count == 0:
                logger.warning(f"Document matched but not modified for email: {email}")
                return JsonResponse({'error': 'Failed to update reset token'}, status=500)

            # Verify the token was stored
            updated_admin = admin_collection.find_one({'email': email})
            stored_token = updated_admin.get('reset_password_token')
            if stored_token != reset_token:
                logger.error(f"Reset token mismatch for email: {email}. Expected: {reset_token}, Found: {stored_token}")
                return JsonResponse({'error': 'Failed to store reset token'}, status=500)

            # Log the stored expiry time
            logger.info(f"Stored token expiry for {email}: {updated_admin.get('reset_password_token_expiry')}")

            # URL-encode the token and email for the reset link
            encoded_token = urllib.parse.quote(reset_token)
            encoded_email = urllib.parse.quote(email)
            reset_link = f'https://snsct-dt-leaderboard.vercel.app/admin/forgot-password-reset-password?token={encoded_token}&email={encoded_email}'
            logger.info(f"Sending reset link to {email}: {reset_link}")

            # Send the reset link via email
            send_mail(
                subject='Reset your password for AI Exam Analyzer',
                message=f"""
                Hi {admin_user.get('name')},

                You requested to reset your password. Please click the following link to reset it: {reset_link}
                This link will expire in 30 minutes.

                If you did not request a password reset, please ignore this email.

                Best regards,
                SuperAdmin Team
                """,
                from_email=None,  # Uses DEFAULT_FROM_EMAIL
                recipient_list=[email],
                fail_silently=False,
            )

            logger.info(f"Password reset email sent successfully to {email}")
            return JsonResponse({'message': 'Password reset link sent to your email.'}, status=200)

        except Exception as e:
            logger.error(f"Error in forgot_password: {str(e)}", exc_info=True)
            return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)
@csrf_exempt
def validate_reset_token_for_admin(request):
    """
    Validates a JWT password reset token. Returns 404 if invalid or expired.
    Expects a GET request with 'token' as a query parameter.
    """
    if request.method == "GET":

        try:
            token = request.GET.get('token')

            if not token or token == 'None':
                logger.warning("Validate reset token request missing or invalid token")
                return JsonResponse({'error': 'Token is required'}, status=400)

            logger.info(f"Validating JWT token: {token}")

            # Decode and verify the JWT token
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                email = payload.get('email')
            except jwt.ExpiredSignatureError:
                logger.warning(f"Token expired: {token}")
                return JsonResponse({'error': 'Invalid or expired token'}, status=404)
            except jwt.InvalidTokenError:
                logger.warning(f"Invalid JWT token: {token}")
                return JsonResponse({'error': 'Invalid or expired token'}, status=404)

            # Verify the token and expiry in the database
            admin_user = admin_collection.find_one({
                'email': email,
                'reset_password_token': token,
                'reset_password_token_expiry': {'$gt': timezone.now()}
            })

            if not admin_user:
                logger.warning(f"No admin found for token: {token} or token expired")
                admin_with_token = admin_collection.find_one({'reset_password_token': token})
                if admin_with_token:
                    logger.info(f"Token found but expired. Expiry: {admin_with_token.get('reset_password_token_expiry')}")
                return JsonResponse({'error': 'Invalid or expired token'}, status=404)

            logger.info(f"Token validated successfully for email: {admin_user.get('email')}")
            return JsonResponse({'message': 'Token is valid'}, status=200)

        except Exception as e:
            logger.error(f"Error in validate_reset_token: {str(e)}", exc_info=True)
            return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def reset_password_for_forgot_password(request):
    """
    Resets the admin's password using a valid JWT reset token for forgot password flow.
    Expects a POST request with JSON body containing 'token' and 'password'.
    Uses the same schema and collection as reset_password.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            token = data.get('token')
            password = data.get('password')

            if not all([token, password]):
                logger.warning("Reset password request missing token or password")
                return JsonResponse({'error': 'Token and password are required'}, status=400)

            # Decode and verify the JWT token
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                email = payload.get('email')
            except jwt.ExpiredSignatureError:
                logger.warning(f"Token expired: {token}")
                return JsonResponse({'error': 'Invalid or expired token'}, status=404)
            except jwt.InvalidTokenError:
                logger.warning(f"Invalid JWT token: {token}")
                return JsonResponse({'error': 'Invalid or expired token'}, status=404)

            # Check if the token is valid and not expired in the database
            admin_user = admin_collection.find_one({
                'email': email,
                'reset_password_token': token,
                'reset_password_token_expiry': {'$gt': timezone.now()}
            })

            if not admin_user:
                logger.warning(f"No admin found for token: {token} or token expired")
                return JsonResponse({'error': 'Invalid or expired token'}, status=404)

            # Validate password complexity (same as reset_password)
            if len(password) < 8:
                logger.warning(f"Password too short for email: {email}")
                return JsonResponse({'error': 'Password must be at least 8 characters long'}, status=400)
            if not re.search(r'[A-Z]', password):
                logger.warning(f"Password missing uppercase letter for email: {email}")
                return JsonResponse({'error': 'Password must contain at least one uppercase letter'}, status=400)
            if not re.search(r'[a-z]', password):
                logger.warning(f"Password missing lowercase letter for email: {email}")
                return JsonResponse({'error': 'Password must contain at least one lowercase letter'}, status=400)
            if not re.search(r'[0-9]', password):
                logger.warning(f"Password missing digit for email: {email}")
                return JsonResponse({'error': 'Password must contain at least one digit'}, status=400)
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                logger.warning(f"Password missing special character for email: {email}")
                return JsonResponse({'error': 'Password must contain at least one special character'}, status=400)

            # Hash the new password and update the admin document (same as reset_password)
            hashed_password = make_password(password)
            result = admin_collection.update_one(
                {'_id': admin_user['_id']},
                {
                    '$set': {
                        'password': hashed_password,
                        'password_set': True,
                        'reset_password_token': None,
                        'reset_password_token_expiry': None
                    }
                }
            )

            if result.modified_count == 0:
                logger.warning(f"Failed to update password for email: {email}")
                return JsonResponse({'error': 'Failed to update password'}, status=500)

            logger.info(f"Password reset successfully for email: {email}")
            return JsonResponse({'message': 'Password reset successfully. You can now log in.'}, status=200)

        except Exception as e:
            logger.error(f"Error in reset_password_for_forgot_password: {str(e)}", exc_info=True)
            return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def reset_password(request):
    """
    Resets the admin's password using a valid reset token.
    Expects a POST request with JSON body containing 'token' and 'password'.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            token = data.get('token')
            password = data.get('password')

            if not all([token, password]):
                return JsonResponse({'error': 'Token and password are required'}, status=400)

            # Check if the token is valid and not expired
            admin_user = admin_collection.find_one({
                'reset_password_token': token,
                'reset_password_token_expiry': {'$gt': timezone.now()}
            })

            if not admin_user:
                return JsonResponse({'error': 'Invalid or expired token'}, status=404)

            # Validate password complexity
            if len(password) < 8:
                return JsonResponse({'error': 'Password must be at least 8 characters long'}, status=400)
            if not re.search(r'[A-Z]', password):
                return JsonResponse({'error': 'Password must contain at least one uppercase letter'}, status=400)
            if not re.search(r'[a-z]', password):
                return JsonResponse({'error': 'Password must contain at least one lowercase letter'}, status=400)
            if not re.search(r'[0-9]', password):
                return JsonResponse({'error': 'Password must contain at least one digit'}, status=400)
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                return JsonResponse({'error': 'Password must contain at least one special character'}, status=400)

            # Hash the new password and update the admin document
            hashed_password = make_password(password)
            admin_collection.update_one(
                {'_id': admin_user['_id']},
                {
                    '$set': {
                        'password': hashed_password,
                        'password_set': True,
                        'reset_password_token': None,
                        'reset_password_token_expiry': None
                    }
                }
            )

            return JsonResponse({'message': 'Password reset successfully. You can now log in.'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def get_detailed_student_tasks(request):
    """
    POST: Retrieve detailed task and subtask points for a specific student by event_id and student_email.
    Returns hierarchical structure even if the student has not been scored yet (all points default to 0).
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method. Use POST."}, status=405)

    try:
        data = json.loads(request.body)
        event_id = data.get("event_id")
        student_email = data.get("student_email")

        if not all([event_id, student_email]):
            return JsonResponse({"error": "event_id and student_email are required"}, status=400)

        # Fetch points and event structure
        points_doc = points_collection.find_one({"event_id": event_id})
        event_doc = tasks_collection.find_one({"_id": ObjectId(event_id)})

        if not event_doc:
            return JsonResponse({"error": "No event data found for this event"}, status=404)

        # Search for the student's score data if available
        student_data = None
        if points_doc:
            for admin_entry in points_doc.get("assigned_to", []):
                for mark in admin_entry.get("marks", []):
                    if mark.get("student_email") == student_email:
                        student_data = mark
                        break
                if student_data:
                    break

        # Create lookup dictionaries
        task_total_points = {}
        subtask_total_points = {}
        total_possible_score = 0

        for level in event_doc.get("levels", []):
            for task in level.get("tasks", []):
                task_total_points[task["task_id"]] = task.get("total_points", 0)
                total_possible_score += task.get("total_points", 0)
                for subtask in task.get("subtasks", []):
                    subtask_total_points[subtask["subtask_id"]] = subtask.get("points", 0)

        # Build score lookup for quick access if points exist
        student_score_lookup = {}
        if student_data:
            for level in student_data.get("score", []):
                for task in level.get("task", []):
                    task_id = task.get("task_id")
                    task_info = {
                        "points": task.get("points", 0),
                        "status": task.get("status", "incomplete"),
                        "points_assigned_on": task.get("points_assigned_on"),
                        "last_updated_on": task.get("last_updated_on"),
                        "subtasks": {sub.get("subtask_id"): sub for sub in task.get("sub_task", [])}
                    }
                    student_score_lookup[task_id] = task_info

        total_score = 0
        levels = []

        for level in event_doc.get("levels", []):
            level_points = 0
            level_data = {
                "level_id": level.get("level_id"),
                "level_name": level.get("level_name"),
                "frequency": level.get("frequency"),
                "total_points": 0,
                "tasks": []
            }

            for task in level.get("tasks", []):
                task_id = task.get("task_id")
                score_info = student_score_lookup.get(task_id, {})
                task_points = score_info.get("points", 0)
                level_points += task_points
                total_score += task_points

                # Convert timestamps
                def parse_time(ts):
                    if isinstance(ts, dict):
                        return ts.get("$date", "")
                    elif isinstance(ts, datetime):
                        return ts.isoformat()
                    return ts or ""

                task_data = {
                    "task_id": task_id,
                    "task_name": task.get("task_name"),
                    "points": task_points,
                    "total_points": task_total_points.get(task_id, 0),
                    "status": score_info.get("status", "incomplete"),
                    "points_assigned_on": parse_time(score_info.get("points_assigned_on", "")),
                    "last_updated_on": parse_time(score_info.get("last_updated_on", "")),
                    "sub_tasks": []
                }

                for sub in task.get("subtasks", []):
                    subtask_id = sub.get("subtask_id")
                    sub_info = score_info.get("subtasks", {}).get(subtask_id, {})
                    subtask_data = {
                        "subtask_id": subtask_id,
                        "subtask_name": sub.get("subtask_name"),
                        "points": sub_info.get("points", 0),
                        "total_points": subtask_total_points.get(subtask_id, 0),
                        "status": sub_info.get("status", "incomplete"),
                        "points_assigned_on": parse_time(sub_info.get("points_assigned_on", "")),
                        "last_updated_on": parse_time(sub_info.get("last_updated_on", ""))
                    }
                    task_data["sub_tasks"].append(subtask_data)

                level_data["tasks"].append(task_data)

            level_data["total_points"] = level_points
            levels.append(level_data)

        return JsonResponse({
            "success": True,
            "message": f"Found data for student {student_data.get('student_name', student_email) if student_data else student_email} in event {event_id}",
            "event_id": event_id,
            "event_name": points_doc.get("event_name") if points_doc else event_doc.get("event_name", ""),
            "student_email": student_email,
            "student_name": student_data.get("student_name") if student_data else "",
            "total_points": total_score,
            "total_possible_score": total_possible_score,
            "levels": levels
        }, status=200)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)
