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
            setup_link = f'https://snsct-leaderboard.vercel.app/admin/setup-password?token={token}'
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
                    task_data = {
                            "task_id": task.get("task_id"),
                            "task_name": task.get("task_name"),
                            "description": task.get("description"),
                            "total_points": task.get("total_points"),
                            "deadline": task.get("deadline"),
                            "deadline_time": task.get("deadline_time"),
                            "full_deadline": task.get("full_deadline"),
                            "frequency": task.get("frequency"),
                            "start_date": task.get("start_date"),
                            "end_date": task.get("end_date"),
                            "level_id": level_id,
                            "level_name": level_name,
                            "event_id": str(doc.get("_id")),
                            "event_name": event_name,
                            "marking_criteria": task.get("marking_criteria"),
                            "subtasks": [
                                {
                                    "subtask_id": subtask.get("subtask_id"),
                                    "name": subtask.get("name"),
                                    "description": subtask.get("description"),
                                    "points": subtask.get("points"),
                                    "deadline": subtask.get("deadline"),
                                    "deadline_time": subtask.get("deadline_time"),
                                    "full_deadline": subtask.get("full_deadline"),
                                    "status": subtask.get("status"),
                                    "marking_criteria": subtask.get("marking_criteria", {})
                                } for subtask in task.get("subtasks", [])
                            ]
                        }
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
    
@csrf_exempt
def manage_task_points(request, event_id, task_id):
    """
    GET: Retrieve points for students in a specific task for the logged-in admin.
    POST: Store student points inside the assigned_to → marks of the specific admin.
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
            
            if mapped_doc:
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

            # ✅ Frequency map setup for levels + subtasks extraction
            level_frequency_map = {}
            if event_doc_task:
                for level in event_doc_task.get("levels", []):
                    level_id_inner = level.get("level_id")
                    frequency = None
                    
                    # Get frequency from ANY task in this level
                    for task in level.get("tasks", []):
                        if task.get("frequency"):
                            frequency = task.get("frequency")
                            break  # Use the first frequency found in this level

                    # Check if this level contains our target task
                    for task in level.get("tasks", []):
                        if task.get("task_id") == task_id:
                            subtasks_for_task = task.get("subtasks", [])
                            task_found = True
                            break

                    if level_id_inner:
                        level_frequency_map[level_id_inner] = frequency



            # ✅ Get existing points data
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
                        
                        if event_doc:
                            admin_entry = next(
                                (a for a in event_doc.get("assigned_to", []) if a.get("admin_id") == admin_id),
                                None
                            )
                            
                            if admin_entry:
                                for student_mark in admin_entry.get("marks", []):
                                    if student_mark.get("student_email") == student_email:
                                        for level in student_mark.get("score", []):
                                            for task in level.get("task", []):
                                                if task.get("task_id") == task_id:
                                                    for sub_task in task.get("sub_task", []):
                                                        if sub_task.get("subtask_id") == subtask_id:
                                                            student_status = sub_task.get("status", "incomplete")
                                                            student_points = sub_task.get("points", 0)
                                                            break
                        
                        task_points.append({
                            "roll_no": student.get("roll_no", student_email.split("@")[0]),
                            "student_name": student.get("name"),
                            "student_email": student_email,
                            "points": student_points,
                            "status": student_status,
                            "subtask_id": subtask_id,
                            "subtask_name": subtask.get("name", ""),
                            "time": None,
                            "updated_time": None
                        })
                        
                        print(f"Added point entry: roll_no={student.get('roll_no', student_email.split('@')[0])}, status={student_status}, subtask_id={subtask_id}")
            else:
                # Handle tasks without subtasks
                for student in all_students:
                    student_email = student.get("email")
                    student_status = "incomplete"
                    student_points = 0
                    
                    if event_doc:
                        admin_entry = next(
                            (a for a in event_doc.get("assigned_to", []) if a.get("admin_id") == admin_id),
                            None
                        )
                        
                        if admin_entry:
                            for student_mark in admin_entry.get("marks", []):
                                if student_mark.get("student_email") == student_email:
                                    for level in student_mark.get("score", []):
                                        for task in level.get("task", []):
                                            if task.get("task_id") == task_id and not task.get("sub_task"):
                                                student_status = task.get("status", "incomplete")
                                                student_points = task.get("points", 0)
                                                break
                        
                    task_points.append({
                        "roll_no": student.get("roll_no", student_email.split("@")[0]),
                        "student_name": student.get("name"),
                        "student_email": student_email,
                        "points": student_points,
                        "status": student_status,
                        "subtask_id": None,
                        "subtask_name": None,
                        "time": None,
                        "updated_time": None
                    })
                    
                    print(f"Added point entry: roll_no={student.get('roll_no', student_email.split('@')[0])}, status={student_status}, task_id={task_id}")

            print(f"level_frequency: {level_frequency_map}")
            return JsonResponse({"points": task_points,"level_frequency": level_frequency_map}, status=200)

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

            # Check if task has subtasks
            event_doc_task = tasks_collection.find_one({"_id": ObjectId(event_id)})
            subtasks_for_task = []
            task_found = False

            # ✅ Frequency map setup for levels + subtasks extraction
            level_frequency_map = {}
            if event_doc_task:
                print(f"🔍 POST: Building frequency map for event_id: {event_id}")
                for level in event_doc_task.get("levels", []):
                    level_id_inner = level.get("level_id")
                    frequency = None
                    print(f"🔍 POST: Processing level_id: {level_id_inner}")
                    
                    # Get frequency from ANY task in this level
                    for task in level.get("tasks", []):
                        if task.get("frequency"):
                            frequency = task.get("frequency")
                            print(f"🔍 POST: Found frequency: {frequency} for level: {level_id_inner}")
                            break  # Use the first frequency found in this level

                    # Check if this level contains our target task
                    for task in level.get("tasks", []):
                        if task.get("task_id") == task_id:
                            subtasks_for_task = task.get("subtasks", [])
                            task_found = True
                            print(f"🔍 POST: Found target task_id: {task_id} in level: {level_id_inner}")
                            break

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

            # Add or update marks for each student
            for student in students:
                student_email = student.get("student_email")
                student_name = student.get("student_name")
                points = student.get("points", 0)
                status = student.get("status", "incomplete")

                if not student_email:
                    continue

                print(f"Processing student: {student_email}, status: {status}, points: {points}")

                student_found = False
                for s in admin_entry.get("marks", []):
                    if s["student_email"] == student_email:
                        student_found = True
                        
                        # ✅ FIRST: Update frequency for ALL existing levels for this student
                        for level in s.get("score", []):
                            existing_level_id = level.get("level_id")
                            expected_frequency = level_frequency_map.get(existing_level_id)
                            current_frequency = level.get("frequency")
                            
                            if current_frequency != expected_frequency:
                                level["frequency"] = expected_frequency
                                print(f"🔁 Updated frequency for existing level {existing_level_id}: {current_frequency} -> {expected_frequency}")
                                updated = True
                            elif "frequency" not in level and expected_frequency is not None:
                                level["frequency"] = expected_frequency
                                print(f"🆕 Added missing frequency for level {existing_level_id} -> {expected_frequency}")
                                updated = True
                        
                        # ✅ SECOND: Process the specific level for the current task
                        level_found = False
                        for level in s.get("score", []):
                            if level["level_id"] == level_id:
                                print(f"Found existing level_id={level_id} for student {student_email}")
                                level_found = True
                                task_found = False
                                for task in level.get("task", []):
                                    if task["task_id"] == task_id:
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
                                                        sub["last_updated_on"] = now_timestamp  # ✅ added
                                                        if "points_assigned_on" not in sub:
                                                            sub["points_assigned_on"] = now_timestamp  # ✅ added (if new)
                                                        updated = True
                                                        print(f"Updated subtask for {student_email}")

                                                    break
                                            
                                            if not subtask_found:
                                                task["sub_task"].append({
                                                "subtask_id": subtask_id,
                                                "subtask_name": subtask_name,
                                                "points": points,
                                                "status": status,
                                                "points_assigned_on": now_timestamp,  # ✅ added
                                                "last_updated_on": now_timestamp      # ✅ added
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
                                                task["last_updated_on"] = now_timestamp  # ✅ added
                                                if "points_assigned_on" not in task:
                                                    task["points_assigned_on"] = now_timestamp  # ✅ added
                                                task["sub_task"] = []  # Ensure no subtasks
                                                updated = True
                                                print(f"Updated task for {student_email}")
                                        break
                                
                                if not task_found:
                                    task_data = {
                                        "task_id": task_id,
                                        "task_name": task_name,
                                        "points": points,
                                        "sub_task": [],
                                        "points_assigned_on": now_timestamp,  # ✅ added
                                        "last_updated_on": now_timestamp      # ✅ added
                                    }
                                    if subtask_id and subtasks_for_task:
                                        task_data["sub_task"] = [{
                                            "subtask_id": subtask_id,
                                            "subtask_name": subtask_name,
                                            "points": points,
                                            "status": status,
                                            "points_assigned_on": now_timestamp,  # ✅ added
                                            "last_updated_on": now_timestamp      # ✅ added
                                        }]
                                        task_data["points"] = points
                                    else:
                                        task_data["status"] = status
                                    level["task"].append(task_data)
                                    updated = True
                                    print(f"Added new task for {student_email}")
                                break
                        
                        if not level_found:
                            print(f"🆕 Creating new level for student {student_email}")
                            print(f"🔍 Level ID: {level_id}")
                            print(f"🔍 Frequency from map: {level_frequency_map.get(level_id)}")
                            level_data = {
                                "level_id": level_id,
                                "level_name": level_name,
                                "frequency": level_frequency_map.get(level_id),  # ✅ Frequency from map
                                "task": [{
                                    "task_id": task_id,
                                    "task_name": task_name,
                                    "points": points,
                                    "points_assigned_on": now_timestamp,  # ✅ added
                                    "last_updated_on": now_timestamp,      # ✅ added
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
                                    "points_assigned_on": now_timestamp,  # ✅ added
                                    "last_updated_on": now_timestamp      # ✅ added
                                }]
                                level_data["task"][0]["points"] = points
                            else:
                                level_data["task"][0]["status"] = status
                            s["score"].append(level_data)
                            updated = True
                            print(f"Added new level for {student_email} with frequency: {level_frequency_map.get(level_id)}")
                        break

                if not student_found:
                    print(f"🆕 Creating new student {student_email}")
                    print(f"🔍 Level ID: {level_id}")
                    print(f"🔍 Frequency from map: {level_frequency_map.get(level_id)}")
                    student_data = {
                        "student_email": student_email,
                        "student_name": student_name,
                        "score": [{
                            "level_id": level_id,
                            "level_name": level_name,
                            "frequency": level_frequency_map.get(level_id),  # ✅ Frequency from map
                            "task": [{
                                "task_id": task_id,
                                "task_name": task_name,
                                "points": points,
                                "points_assigned_on": now_timestamp,  # ✅ added
                                "last_updated_on": now_timestamp,      # ✅ added
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
                            "points_assigned_on": now_timestamp,  # ✅ added
                            "last_updated_on": now_timestamp      # ✅ added
                        }]
                        student_data["score"][0]["task"][0]["points"] = points
                    else:
                        student_data["score"][0]["task"][0]["status"] = status
                    admin_entry.setdefault("marks", []).append(student_data)
                    updated = True
                    print(f"Added new student {student_email} with level frequency: {level_frequency_map.get(level_id)}")

            print(f"Updated flag: {updated}")
            
            if updated:
                # Add debugging before database update
                print("🔍 DEBUG: About to update database with event_doc structure:")
                for assigned_admin in event_doc.get("assigned_to", []):
                    if assigned_admin.get("admin_id") == admin_id:
                        for mark in assigned_admin.get("marks", []):
                            for score in mark.get("score", []):
                                print(f"🔍 Level {score.get('level_id')}: frequency = {score.get('frequency')}")
                
                result = points_collection.replace_one({"_id": event_doc["_id"]}, event_doc)
                print(f"Database update result: {result.modified_count} documents modified")
                
                # Add debugging after database update to verify
                updated_doc = points_collection.find_one({"_id": event_doc["_id"]})
                print("🔍 DEBUG: After database update, verifying frequency in DB:")
                for assigned_admin in updated_doc.get("assigned_to", []):
                    if assigned_admin.get("admin_id") == admin_id:
                        for mark in assigned_admin.get("marks", []):
                            for score in mark.get("score", []):
                                print(f"🔍 DB Level {score.get('level_id')}: frequency = {score.get('frequency')}")

            return JsonResponse({
                "message": "Points updated successfully" if updated else "No changes made",
                "updated": updated,
                "students_processed": len(students)
            }, status=200)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return JsonResponse({"error": str(e)}, status=500)

    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)
    
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
            reset_link = f'https://snsct-leaderboard.vercel.app/admin/forgot-password-reset-password?token={encoded_token}&email={encoded_email}'
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
    Returns hierarchical structure of levels, tasks, and subtasks with points, total_points, status, and timestamps.
    No JWT authentication required.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method. Use POST."}, status=405)

    try:
        data = json.loads(request.body)
        event_id = data.get("event_id")
        student_email = data.get("student_email")

        if not all([event_id, student_email]):
            return JsonResponse({"error": "event_id and student_email are required"}, status=400)

        # Get event task structure
        event_doc = tasks_collection.find_one({"_id": ObjectId(event_id)})
        if not event_doc:
            return JsonResponse({"error": "No event data found for this event"}, status=404)

        # Try finding the student's points
        points_doc = points_collection.find_one({"event_id": event_id})
        student_data = None
        if points_doc:
            for admin_entry in points_doc.get("assigned_to", []):
                for mark in admin_entry.get("marks", []):
                    if mark.get("student_email") == student_email:
                        student_data = mark
                        break
                if student_data:
                    break

        # Create lookup for total task and subtask points
        task_total_points = {}
        subtask_total_points = {}
        total_possible_score = 0

        for level in event_doc.get("levels", []):
            for task in level.get("tasks", []):
                task_total_points[task["task_id"]] = task.get("total_points", 0)
                total_possible_score += task.get("total_points", 0)
                for subtask in task.get("subtasks", []):
                    subtask_total_points[subtask["subtask_id"]] = subtask.get("points", 0)

        # If no data, construct from structure with zero points
        if not student_data:
            levels = []
            for level in event_doc.get("levels", []):
                level_data = {
                    "level_id": level.get("level_id"),
                    "level_name": level.get("level_name", ""),
                    "frequency": level.get("frequency"),
                    "total_points": 0,
                    "tasks": []
                }
                for task in level.get("tasks", []):
                    task_data = {
                        "task_id": task.get("task_id"),
                        "task_name": task.get("task_name"),
                        "points": 0,
                        "total_points": task_total_points.get(task.get("task_id"), 0),
                        "status": "incomplete",
                        "points_assigned_on": "",
                        "last_updated_on": "",
                        "sub_tasks": []
                    }
                    for subtask in task.get("subtasks", []):
                        subtask_data = {
                            "subtask_id": subtask.get("subtask_id"),
                            "subtask_name": subtask.get("subtask_name"),
                            "points": 0,
                            "total_points": subtask_total_points.get(subtask.get("subtask_id"), 0),
                            "status": "incomplete",
                            "points_assigned_on": "",
                            "last_updated_on": ""
                        }
                        task_data["sub_tasks"].append(subtask_data)
                    level_data["tasks"].append(task_data)
                levels.append(level_data)

            return JsonResponse({
                "success": True,
                "message": f"No score data found for student {student_email}. Returning zeroed data.",
                "event_id": event_id,
                "event_name": event_doc.get("event_name", ""),
                "student_email": student_email,
                "student_name": "",
                "total_points": 0,
                "total_possible_score": total_possible_score,
                "levels": levels
            }, status=200)

        # If data exists, format it normally
        levels = []
        total_points = 0
        for score in student_data.get("score", []):
            level_points = sum(task.get("points", 0) for task in score.get("task", []))
            total_points += level_points
            level_data = {
                "level_id": score.get("level_id"),
                "level_name": score.get("level_name", ""),
                "frequency": score.get("frequency"),
                "total_points": level_points,
                "tasks": []
            }
            for task in score.get("task", []):
                points_assigned_on = task.get("points_assigned_on", "")
                if isinstance(points_assigned_on, dict):
                    points_assigned_on = points_assigned_on.get("$date", "")
                elif isinstance(points_assigned_on, datetime):
                    points_assigned_on = points_assigned_on.isoformat()

                last_updated_on = task.get("last_updated_on", "")
                if isinstance(last_updated_on, dict):
                    last_updated_on = last_updated_on.get("$date", "")
                elif isinstance(last_updated_on, datetime):
                    last_updated_on = last_updated_on.isoformat()

                task_data = {
                    "task_id": task.get("task_id"),
                    "task_name": task.get("task_name"),
                    "points": task.get("points", 0),
                    "total_points": task_total_points.get(task.get("task_id"), 0),
                    "status": task.get("status", "incomplete"),
                    "points_assigned_on": points_assigned_on,
                    "last_updated_on": last_updated_on,
                    "sub_tasks": []
                }
                for subtask in task.get("sub_task", []):
                    sub_points_assigned_on = subtask.get("points_assigned_on", "")
                    if isinstance(sub_points_assigned_on, dict):
                        sub_points_assigned_on = sub_points_assigned_on.get("$date", "")
                    elif isinstance(sub_points_assigned_on, datetime):
                        sub_points_assigned_on = sub_points_assigned_on.isoformat()

                    sub_last_updated_on = subtask.get("last_updated_on", "")
                    if isinstance(sub_last_updated_on, dict):
                        sub_last_updated_on = sub_last_updated_on.get("$date", "")
                    elif isinstance(sub_last_updated_on, datetime):
                        sub_last_updated_on = sub_last_updated_on.isoformat()

                    subtask_data = {
                        "subtask_id": subtask.get("subtask_id"),
                        "subtask_name": subtask.get("subtask_name"),
                        "points": subtask.get("points", 0),
                        "total_points": subtask_total_points.get(subtask.get("subtask_id"), 0),
                        "status": subtask.get("status", "incomplete"),
                        "points_assigned_on": sub_points_assigned_on,
                        "last_updated_on": sub_last_updated_on
                    }
                    task_data["sub_tasks"].append(subtask_data)
                level_data["tasks"].append(task_data)
            levels.append(level_data)

        return JsonResponse({
            "success": True,
            "message": f"Found data for student {student_data.get('student_name', student_email)} in event {event_id}",
            "event_id": event_id,
            "event_name": points_doc.get("event_name", event_doc.get("event_name", "")),
            "student_email": student_email,
            "student_name": student_data.get("student_name", ""),
            "total_points": total_points,
            "total_possible_score": total_possible_score,
            "levels": levels
        }, status=200)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)