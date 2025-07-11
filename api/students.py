from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from datetime import datetime, timedelta
from django.contrib.auth.hashers import make_password, check_password
from pymongo import MongoClient
from django.views.decorators.http import require_POST
from bson import ObjectId
from dotenv import load_dotenv
import os
import jwt
import random
import string
import smtplib
from email.mime.text import MIMEText
from django.conf import settings
import secrets
from datetime import datetime, timedelta
from django.http import JsonResponse
import json
from django.utils import timezone
from datetime import timedelta
import re

load_dotenv()

JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'

# Connect to MongoDB
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
print(client)  # Debugging line to check if client is connected
db = client['Leaderboard']
mapped_events_collection = db['Mapped_Events']
points_collection = db['Points']
tasks_collection= db['events']
student_collection = db['users']
admin_collection = db['admin']



def generate_verification_code():
    """Generate a random 6-digit verification code."""
    return ''.join(random.choices(string.digits, k=6))

def store_verification_code(email, code):
    """Store verification code with expiry time (10 minutes)."""
    expiry_time = datetime.now() + timedelta(minutes=10)
    student_collection.update_one(
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
    student = student_collection.find_one({'email': email})
    if not student or 'verification_code' not in student:
        return False

    if student['verification_expiry'] < datetime.now():
        return False

    if student.get('verification_attempts', 0) >= 3:  # Limit attempts
        return False

    # Increment attempts
    student_collection.update_one(
        {'email': email},
        {'$inc': {'verification_attempts': 1}}
    )

    return student['verification_code'] == code

def reset_login_attempts(email):
    """Reset login attempts for a given email."""
    student_collection.update_one(
        {'email': email},
        {
            '$set': {
                'login_attempts': 0
            }
        }
    )

def increment_login_attempts(email):
    """Increment login attempts and set account to Inactive if threshold reached."""
    student = student_collection.find_one({'email': email})
    current_attempts = student.get('login_attempts', 0) + 1
    account_deactivated = False

    if current_attempts >= 3:  # Deactivation threshold
        # Deactivate the account instead of using a time-based lockout
        student_collection.update_one(
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
        student_collection.update_one(
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
    student = student_collection.find_one({'email': email})
    if not student:
        return False

    return student.get('status') == 'Inactive'

#======================================================= FUNCTIONS ===========================================================================

def generate_tokens(student_user, name, email, student_id):
    """Generates JWT tokens for student authentication.

    Args:
        student_user (str): The student user ID.
        name (str): The student user's name.
        student_id (str): The student ID.
        department (str): The department associated with the student.

    Returns:
        dict: A dictionary containing the JWT token.
    """
    payload = {
        '_id': str(student_user),
        'name': name,
        'email' : email,
        'roll_no': student_id,
        "exp": datetime.utcnow() + timedelta(days=1),
        "iat": datetime.utcnow(),
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {'jwt': token}

#======================================================= STUDENT ===========================================================================

def generate_secure_token(length=32):
    """Generate a secure random token."""
    alphabet = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(alphabet) for _ in range(length))
    return token

def validate_token(token):
    """Validate the token and check if it has expired."""
    student_user = student_collection.find_one({'password_setup_token': token})
    if not student_user:
        return False, "Invalid token"

    if datetime.now() > student_user['password_setup_token_expiry']:
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

    # Hash the password and update the student user
    hashed_password = make_password(password)
    student_collection.update_one(
        {'password_setup_token': token},
        {
            '$set': {
                'password': hashed_password,
                'password_set': True,
                'password_setup_token': None,
                'password_setup_token_expiry': None,
                'status': "Active"
            }
        }
    )

    return True, "Password set successfully"

@csrf_exempt
def student_signup(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            name = data.get('name')
            email = data.get('email')
            student_id = data.get('student_id')
            department = data.get('department')
            password = data.get('password')
            token = data.get('token')

            if not all([name, email, student_id, department, password, token]):
                return JsonResponse({'error': 'All fields are required'}, status=400)

            # Verify token
            is_valid, message = validate_token(token)
            if not is_valid:
                return JsonResponse({'error': message}, status=400)

            # Check if student_id is already used by another user
            if student_collection.find_one({'student_id': student_id}):
                return JsonResponse({'error': 'Student ID already exists'}, status=400)

            # Check if email exists in Users collection
            existing_user = student_collection.find_one({'email': email})
            if not existing_user:
                return JsonResponse({'error': 'Invalid email for signup'}, status=400)

            # If email exists and account is fully registered (has all required fields)
            if existing_user and existing_user.get('password_set', False) and all(
                existing_user.get(field) for field in ['name', 'student_id', 'department', 'password']
            ):
                return JsonResponse({'error': 'Email already registered with a complete account'}, status=400)

            # Validate password complexity
            if len(password) < 8:
                return JsonResponse({'error': 'Password must be at least 8 characters long'}, status=400)
            if not re.search(r'[A-Z]', password):
                return JsonResponse({'error': 'Password must contain at least one uppercase letter'}, status=400)
            if not re.search(r'[a-z]', password):
                return JsonResponse({'error': 'Password must contain at least one lowercase letter'}, status=400)
            if not re.search(r'[0-9]', password):
                return JsonResponse({'error': 'Password must contain at least one number'}, status=400)
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                return JsonResponse({'error': 'Password must contain at least one special character'}, status=400)

            # Hash the password
            hashed_password = make_password(password)

            # Prepare user data
            user_data = {
                'name': name,
                'student_id': student_id,
                'department': department,
                'password': hashed_password,
                'password_set': True,
                'password_setup_token': None,
                'password_setup_token_expiry': None,
                'status': 'Active',
                'created_at': datetime.now(),
                'last_login': None,
                'login_attempts': 0,
                'total_score': 0,
                'tests_taken': 0,
                'average_score': 0
            }

            if existing_user:
                # Update existing incomplete user record
                student_collection.update_one(
                    {'email': email, 'password_setup_token': token},
                    {'$set': user_data}
                )
            else:
                # Insert new user record
                user_data['email'] = email
                student_collection.insert_one(user_data)

            return JsonResponse({'message': 'Student registered successfully. You can now login.'}, status=201)

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
            student_user = student_collection.find_one({
                'password_setup_token': token,
                'password_setup_token_expiry': {'$gt': timezone.now()}
            })

            if not student_user:
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
            token = data.get("token")
            password = data.get("password")

            # Validate token
            student = student_collection.find_one({"password_setup_token": token})
            if not student:
                return JsonResponse({"error": "Invalid token"}, status=400)
            if datetime.now() > student["password_setup_token_expiry"]:
                return JsonResponse({"error": "Token has expired"}, status=400)

            # Validate password complexity
            if len(password) < 8:
                return JsonResponse({"error": "Password must be at least 8 characters long"}, status=400)
            if not re.search(r'[A-Z]', password):
                return JsonResponse({"error": "Password must contain at least one uppercase letter"}, status=400)
            if not re.search(r'[a-z]', password):
                return JsonResponse({"error": "Password must contain at least one lowercase letter"}, status=400)
            if not re.search(r'[0-9]', password):
                return JsonResponse({"error": "Password must contain at least one number"}, status=400)
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                return JsonResponse({"error": "Password must contain at least one special character"}, status=400)

            # Hash the password and update the student document
            hashed_password = make_password(password)
            student_collection.update_one(
                {"password_setup_token": token},
                {
                    "$set": {
                        "password": hashed_password,
                        "password_set": True,
                        "password_setup_token": None,
                        "password_setup_token_expiry": None,
                        "status": "Active"  # Update status to Active
                    }
                }
            )
            return JsonResponse({"message": "Password set successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=400)

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
def check_token_validity(request):
    if request.method == "GET":
        try:
            token = request.GET.get('token')
            if not token:
                return JsonResponse({'error': 'Token is required'}, status=400)

            # Check if the token exists and is not expired
            student_user = student_collection.find_one({
                'password_setup_token': token,
                'password_setup_token_expiry': {'$gt': timezone.now()}
            })

            if not student_user:
                return JsonResponse({'error': 'Invalid or expired token'}, status=404)

            return JsonResponse({
                'message': 'Token is valid',
                'email': student_user.get('email')
            }, status=200)

        except Exception as e:
            return JsonResponse({'error': f'Internal Server Error: {str(e)}'}, status=500)
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def student_login(request):
    """Authenticates a student user, generates a JWT token, and updates attendance.

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
            print(f"Login attempt with email: {email}")

            if not email:
                return JsonResponse({'error': 'Email is required'}, status=400)
            if not password:
                return JsonResponse({'error': 'Password is required'}, status=400)

            # Check if account is deactivated
            if check_account_status(email):
                return JsonResponse(
                    {'error': 'Account has been deactivated due to too many failed login attempts. Contact the administrator.'},
                    status=403
                )

            # Fetch student user
            student_user = student_collection.find_one({'email': email})
            print(f"Student user fetched: {student_user}")
            if not student_user:
                return JsonResponse({'error': f'Invalid email. No account found with email: {email}'}, status=401)

            if student_user.get('status') != 'Active':
                return JsonResponse({'error': 'Account is inactive. Contact the administrator.'}, status=403)

            if not student_user.get('password') or not student_user.get('email'):
                return JsonResponse({'error': 'Invalid student user data'}, status=500)

            # Validate password
            if not check_password(password, student_user['password']):
                attempts, account_deactivated = increment_login_attempts(email)
                if account_deactivated:
                    return JsonResponse({'error': 'Account has been deactivated due to too many failed attempts. Contact the administrator.'}, status=403)
                return JsonResponse({'error': f'Invalid password. {3 - attempts} attempts remaining before account deactivation'}, status=401)


            reset_login_attempts(email)
            current_datetime = datetime.now()
            current_date = current_datetime.date()
            
            # Get attendance tracking data
            current_streak = student_user.get('login_streak', 0)
            max_streak = student_user.get('max_login_streak', 0)
            attendance_percentage = student_user.get('attendance_percentage', 100.0)
            account_creation_date = student_user.get('created_at')
            last_login = student_user.get('last_login')
            login_history = student_user.get('login_history', [])
            
            # Check if already logged in today (to avoid duplicate attendance entries)
            already_logged_in_today = False
            if last_login:
                last_login_date = last_login.date() if hasattr(last_login, 'date') else last_login
                if last_login_date == current_date:
                    already_logged_in_today = True
            
            # Update attendance only if not already logged in today
            if not already_logged_in_today:
                # Calculate streak based on days between logins
                if last_login:
                    last_login_date = last_login.date() if hasattr(last_login, 'date') else last_login
                    
                    # Ensure last_login is not in the future
                    if last_login_date > current_date:
                        last_login_date = current_date
                    
                    days_difference = (current_date - last_login_date).days
                    
                    if days_difference == 0:
                        # Same day login - don't increment streak
                        pass
                    elif days_difference == 1:
                        # Consecutive day login - increment streak
                        current_streak += 1
                        
                        # Improve attendance percentage slightly for consecutive logins
                        if attendance_percentage < 100.0:
                            attendance_percentage = min(100.0, attendance_percentage + 0.5)
                    else:
                        # More than one day gap - reset streak to 1
                        current_streak = 1
                        
                        # Calculate attendance percentage penalty
                        # Calculate total days since account creation
                        if account_creation_date:
                            total_days = (current_date - account_creation_date.date()).days + 1
                            
                            # Get unique login dates (ignoring multiple logins on same day)
                            unique_login_dates = set()
                            for login_time in login_history:
                                login_date = login_time.date() if hasattr(login_time, 'date') else login_time
                                unique_login_dates.add(login_date)
                            
                            # Add today's date to unique login dates
                            unique_login_dates.add(current_date)
                            
                            # Calculate attendance percentage
                            days_expected = max(1, total_days)
                            days_attended = len(unique_login_dates)
                            new_attendance = (days_attended / days_expected) * 100
                            
                            # Apply a smoother transition
                            attendance_percentage = (0.7 * new_attendance) + (0.3 * attendance_percentage)
                else:
                    # First login - start streak at 1
                    current_streak = 1
                
                # Ensure minimum streak of 1
                if current_streak == 0:
                    current_streak = 1
                
                # Cap attendance percentage between 0 and 100
                attendance_percentage = max(0.0, min(100.0, attendance_percentage))
                    
                # Update max streak if current streak is higher
                if current_streak > max_streak:
                    max_streak = current_streak
                
                # Add current datetime to login history
                login_history.append(current_datetime)
            
            # Update student document with new information
            update_data = {
                'last_login': current_datetime,
                'login_streak': current_streak,
                'max_login_streak': max_streak,
                'attendance_percentage': round(attendance_percentage, 2),
                'login_history': login_history
            }
            
            student_collection.update_one(
                {'_id': student_user['_id']},
                {'$set': update_data}
            )

            # Generate token
            token = generate_tokens(
                student_user=student_user['_id'],
                name=student_user['name'],
                email=student_user['email'],
                student_id=student_user.get('student_id')
            )

            # In the student_login function, modify the JsonResponse around line 555:

            # Set token in cookie
            response = JsonResponse({
                "message": "Login successful",
                "attendance": {
                    'current_streak': current_streak,
                    'max_streak': max_streak,
                    'jwt': token['jwt'],
                    'attendance_percentage': round(attendance_percentage, 2),
                    'last_login': current_datetime.isoformat(),
                    'login_count': len(login_history)
                }  # Remove the conditional check that sets this to None
            }, status=200)

            # response.set_cookie(
            #     key="jwt",
            #     value=token['jwt'],
            #     httponly=False,
            #     samesite='None',   # Use 'None' + secure=True for cross-domain
            #     secure=True      # Set to True in production with HTTPS
            # )

            return response

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format in request body'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def send_reset_link(request):
    """
    Endpoint to send password reset link.
    Expects email in request body.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        data = json.loads(request.body)
        email = data.get('email')

        if not email:
            return JsonResponse({"error": "Email is required"}, status=400)

        # Check if email exists in student collection
        student = student_collection.find_one({'email': email})
        if not student:
            return JsonResponse({"error": "Email not found"}, status=404)

        # Generate JWT token
        payload = {
            'email': email,
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

        # Store the token and its expiry time in the database
        expiry_time = datetime.now() + timedelta(hours=1)
        student_collection.update_one(
            {'email': email},
            {'$set': {'reset_token': token, 'reset_token_expiry': expiry_time}}
        )

        # Send email with reset link
        try:
            reset_link = f'https://snsct-leaderboard.vercel.app/studentresetpassword?token={token}&email={email}'
            subject = 'Password Reset Link'
            message = f'Click the following link to reset your password: {reset_link}\nThis link will expire in 1 hour.'

            # Create SMTP connection
            server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
            server.ehlo()
            server.starttls()
            server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)

            # Create email message
            msg = MIMEText(message)
            msg['Subject'] = subject
            msg['From'] = settings.EMAIL_HOST_USER
            msg['To'] = email

            # Send email
            server.send_message(msg)
            server.quit()

            return JsonResponse({"message": "Password reset link sent successfully"}, status=200)

        except Exception as e:
            print(f"Email sending failed with error: {str(e)}")
            return JsonResponse({"error": f"Failed to send email: {str(e)}"}, status=500)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
@csrf_exempt
def reset_password(request):
    """
    Endpoint to reset password using the token.
    Expects token, email, and new_password in request body.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        data = json.loads(request.body)
        token = data.get('token')
        email = data.get('email')
        new_password = data.get('new_password')

        if not all([token, email, new_password]):
            return JsonResponse({"error": "Missing required fields"}, status=400)

        # Check if token is valid and not expired
        student = student_collection.find_one({'email': email, 'reset_token': token})
        if not student or student.get('reset_token_expiry') < datetime.now():
            return JsonResponse({"error": "Invalid or expired token"}, status=400)

        # Update password and clean up token fields
        hashed_password = make_password(new_password)
        result = student_collection.update_one(
            {'email': email},
            {
                '$set': {'password': hashed_password},
                '$unset': {
                    'reset_token': "",
                    'reset_token_expiry': ""
                }
            }
        )

        if result.modified_count == 0:
            return JsonResponse({"error": "Failed to update password"}, status=500)

        return JsonResponse({"message": "Password reset successful"}, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def get_student_profile(request):
    """Get student profile using 'id' passed in the query string."""
    if request.method != "GET":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        student_id = request.GET.get('id')  # 🟢 Expecting ?id= from query params
        if not student_id:
            return JsonResponse({"error": "Student ID is required"}, status=400)

        student = student_collection.find_one({'_id': ObjectId(student_id)})
        if not student:
            return JsonResponse({"error": "Student not found"}, status=404)

        profile_data = {
            'id': str(student['_id']),
            'name': student['name'],
            'email': student['email'],
            'student_id': student['student_id'],
            'department': student['department'],
            'total_score': student.get('total_score', 0),
            'tests_taken': student.get('tests_taken', 0),
            'average_score': student.get('average_score', 0),
            'last_login': student.get('last_login'),
            'created_at': student.get('created_at'),
            'status': student.get('status', 'Active')
        }

        return JsonResponse({"student": profile_data}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def get_student_dashboard_data(request):
    """Get dashboard data for student."""
    if request.method != "GET":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        student_id = request.GET.get('student_id')
        
        if not student_id:
            return JsonResponse({"error": "Student ID is required"}, status=400)

        # Find student in database
        student = student_collection.find_one({'_id': ObjectId(student_id)})
        
        if not student:
            return JsonResponse({"error": "Student not found"}, status=404)

        # Get leaderboard data (top 10 students)
        leaderboard = list(student_collection.find(
            {'status': 'Active'}, 
            {'name': 1, 'student_id': 1, 'total_score': 1, 'tests_taken': 1, 'average_score': 1}
        ).sort('total_score', -1).limit(10))

        # Convert ObjectId to string for JSON serialization
        for student_data in leaderboard:
            student_data['_id'] = str(student_data['_id'])

        # Get student's rank
        all_students = list(student_collection.find(
            {'status': 'Active'}, 
            {'_id': 1, 'total_score': 1}
        ).sort('total_score', -1))
        
        student_rank = None
        for idx, s in enumerate(all_students):
            if str(s['_id']) == student_id:
                student_rank = idx + 1
                break

        dashboard_data = {
            'student_profile': {
                'id': str(student['_id']),
                'name': student['name'],
                'email': student['email'],
                'student_id': student['student_id'],
                'department': student['department'],
                'total_score': student.get('total_score', 0),
                'tests_taken': student.get('tests_taken', 0),
                'average_score': student.get('average_score', 0),
                'rank': student_rank or 'N/A'
            },
            'leaderboard': leaderboard,
            'total_students': student_collection.count_documents({'status': 'Active'})
        }

        return JsonResponse(dashboard_data, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def student_signup_direct(request):
    """Direct student signup without email verification - for development only"""
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            name = data.get('name')
            email = data.get('email')
            student_id = data.get('student_id')
            department = data.get('department')
            password = data.get('password')

            if not all([name, email, student_id, department, password]):
                return JsonResponse({'error': 'All fields are required'}, status=400)

            # Validate password complexity
            if len(password) < 8:
                return JsonResponse({'error': 'Password must be at least 8 characters long'}, status=400)

            if not any(char.isupper() for char in password):
                return JsonResponse({'error': 'Password must contain at least one uppercase letter'}, status=400)

            if not any(char.islower() for char in password):
                return JsonResponse({'error': 'Password must contain at least one lowercase letter'}, status=400)

            if not any(char.isdigit() for char in password) and not any(char in '!@#$%^&*(),.?":{}|<>' for char in password):
                return JsonResponse({'error': 'Password must contain at least one number or special character'}, status=400)

            # Hash the password
            hashed_password = make_password(password)

            # Check if user exists
            existing_user = student_collection.find_one({'email': email})
            if existing_user:
                # Update the existing user
                student_collection.update_one(
                    {'email': email},
                    {'$set': {
                        'name': name,
                        'student_id': student_id,
                        'department': department,
                        'password': hashed_password,
                        'password_set': True,
                        'status': "Active",
                        'created_at': existing_user.get('created_at', datetime.now()),
                        'last_login': None,
                        'login_attempts': 0,
                        'total_score': 0,
                        'tests_taken': 0,
                        'average_score': 0,
                        'password_setup_token': None,
                        'password_setup_token_expiry': None
                    }}
                )
            else:
                # Insert if doesn't exist
                student_user = {
                    'name': name,
                    'email': email,
                    'student_id': student_id,
                    'department': department,
                    'password': hashed_password,
                    'password_set': True,
                    'status': "Active",
                    'created_at': datetime.now(),
                    'last_login': None,
                    'login_attempts': 0,
                    'total_score': 0,
                    'tests_taken': 0,
                    'average_score': 0
                }
                student_collection.insert_one(student_user)

            return JsonResponse({'message': 'Student registered successfully. You can now login.'}, status=201)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def get_student_tasks(request):
    """
    Fetch tasks from a specific event in the Events collection for students.
    Extracts tasks from the nested levels structure for a particular event.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            event_id = data.get('event_id')  # or use data.get('load', {}).get('event_id') if nested
            
            if not event_id:
                return JsonResponse({'error': 'Event ID is required'}, status=400)

            tasks_collection = db['events']
            
            try:
                event = tasks_collection.find_one({'_id': ObjectId(event_id)})
            except:
                return JsonResponse({'error': 'Invalid event ID format'}, status=400)

            if not event:
                return JsonResponse({'error': 'Event not found'}, status=404)

            tasks_list = []
            total_tasks = 0
            event_id_str = str(event['_id'])
            event_name = event.get('event_name', 'Unnamed Event')
            levels = event.get('levels', [])

            for level in levels:
                level_name = level.get('level_name', '')
                tasks = level.get('tasks', [])

                for task in tasks:
                    created_at = ''
                    updated_at = ''

                    if 'created_at' in event:
                        created_at = event['created_at'].isoformat() if isinstance(event['created_at'], datetime) else str(event['created_at'])

                    if 'updated_at' in event:
                        updated_at = event['updated_at'].isoformat() if isinstance(event['updated_at'], datetime) else str(event['updated_at'])

                    deadline = task.get('full_deadline', task.get('deadline', ''))
                    if deadline and isinstance(deadline, str) and 'T' not in deadline:
                        deadline_time = task.get('deadline_time', '23:59')
                        deadline = f"{deadline}T{deadline_time}:00"

                    task_dict = {
                        'id': task.get('task_id', ''),
                        'event_id': event_id_str,
                        'event_name': event_name,
                        'level_id': level.get('level_id', ''),
                        'level_name': level_name,
                        'title': task.get('task_name', ''),
                        'description': task.get('description', ''),
                        'difficulty': 'Medium',
                        'points': task.get('total_points', 0),
                        'category': 'General',
                        'deadline': deadline,
                        'frequency': task.get('frequency', 'Once'),
                        'start_date': task.get('start_date', ''),
                        'end_date': task.get('end_date', ''),
                        'status': task.get('task_status', 'pending'),
                        'created_at': created_at,
                        'updated_at': updated_at,
                        'subtasks': task.get('subtasks', []),
                        'requirements': [],
                        'resources': [],
                        'estimated_time': '',
                        'tags': [],
                        'marking_criteria': task.get('marking_criteria', {}),
                        'last_updated': task.get('last_updated'),
                        'next_update_due': task.get('next_update_due'),
                        'update_history': task.get('update_history', [])
                    }

                    tasks_list.append(task_dict)
                    total_tasks += 1

            return JsonResponse({
                'success': True,
                'event_id': event_id_str,
                'event_name': event_name,
                'tasks': tasks_list,
                'total_tasks': total_tasks
            }, status=200)

        except Exception as e:
            return JsonResponse({'error': f'Server error: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def get_student_events(request):
    """
    Fetch events allocated to the authenticated student based on their email in Mapped_Events.
    Returns a list of events with event_id, event_name, number_of_levels, and updated_at.
    """
    if request.method != "GET":
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        # Get JWT token from cookies or Authorization header
        jwt_token = request.COOKIES.get('jwt') or request.headers.get('Authorization', '').replace('Bearer ', '')
        if not jwt_token:
            return JsonResponse({'error': 'Authentication token missing'}, status=401)

        # Decode JWT to get student email
        try:
            payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            student_email = payload.get('email')
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return JsonResponse({'error': 'Invalid or expired token'}, status=401)

        # Verify student exists
        student = student_collection.find_one({"email": student_email})
        if not student:
            return JsonResponse({'error': 'Student not found'}, status=404)

        # Find mapped events where the student is assigned
        mapped_events = mapped_events_collection.find({
            "assigned_admins.users.email": student_email
        })

        # Collect event IDs
        event_ids = [event["event_id"] for event in mapped_events]

        # Fetch event details from tasks_collection
        event_list = []
        for event_id in event_ids:
            event = tasks_collection.find_one({"_id": ObjectId(event_id)})
            if event:
                event_list.append({
                    "event_id": str(event["_id"]),
                    "event_name": event.get("event_name", "Unnamed Event"),
                    "number_of_levels": len(event.get("levels", [])),
                    "updated_at": event.get("updated_at", datetime.now().strftime("%Y-%m-%d"))
                })

        return JsonResponse({
            "success": True,
            "events": event_list
        }, status=200)

    except Exception as e:
        return JsonResponse({'error': f'Server error: {str(e)}'}, status=500)
    
@csrf_exempt
def get_event_details(request):
    """
    Fetch complete details of an event from the Tasks collection using event_id
    
    Expects event_id as a query parameter
    Returns the complete event object including all levels, tasks, and subtasks
    """
    if request.method != "GET":
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    try:
        # Get event_id from query parameters
        event_id = request.GET.get('event_id')
        
        if not event_id:
            return JsonResponse({'error': 'Event ID is required'}, status=400)
        
        # Try to find event in the Tasks collection
        event = None
        
        # Check in the primary Tasks collection first
        tasks_collection = db['events']
        event = tasks_collection.find_one({'_id': ObjectId(event_id)})
        
        # If not found, check other possible collections
        if not event:
            possible_collections = ['tasks', 'Events', 'events']
            for collection_name in possible_collections:
                if collection_name in db.list_collection_names():
                    collection = db[collection_name]
                    event = collection.find_one({'event_id': event_id})
                    if event:
                        print(f"Found event in alternative collection: {collection_name}")
                        break
        
        if not event:
            return JsonResponse({'error': 'Event not found'}, status=404)
        
        # Convert ObjectId to string for JSON serialization
        event['_id'] = str(event['_id'])
        
        # Handle date fields
        if 'created_at' in event and isinstance(event['created_at'], datetime):
            event['created_at'] = event['created_at'].isoformat()
        if 'updated_at' in event and isinstance(event['updated_at'], datetime):
            event['updated_at'] = event['updated_at'].isoformat()
        
        # Process levels to ensure all nested dates are properly formatted
        if 'levels' in event and isinstance(event['levels'], list):
            for level in event['levels']:
                if 'tasks' in level and isinstance(level['tasks'], list):
                    for task in level['tasks']:
                        # Format deadline if it's a datetime
                        if 'deadline' in task and isinstance(task['deadline'], datetime):
                            task['deadline'] = task['deadline'].isoformat()
                        
                        # Process subtasks
                        if 'subtasks' in task and isinstance(task['subtasks'], list):
                            for subtask in task['subtasks']:
                                if 'deadline' in subtask and isinstance(subtask['deadline'], datetime):
                                    subtask['deadline'] = subtask['deadline'].isoformat()
        
        return JsonResponse({
            'success': True,
            'event': event
        }, status=200)
        
    except Exception as e:
        import traceback
        print(f"Error in get_event_details: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'error': f'Server error: {str(e)}'}, status=500)
    
@csrf_exempt
def student_attendance(request):
    """
    Track student attendance and calculate login streaks and attendance percentage
    
    This function:
    1. Updates the student's login streak when they log in
    2. Resets streak to 1 if more than 1 day has passed since last login
    3. Increments streak if they've logged in on consecutive days
    4. Calculates attendance percentage based on login history vs expected days
    5. Returns the current streak and attendance information
    6. Ensures login count only increases once per day
    """
    if request.method != "POST":
        return JsonResponse({'error': 'Invalid request method'}, status=405)
        
    try:
        # Get JWT token from request (cookies or Authorization header)
        jwt_token = request.COOKIES.get('jwt')
        
        if not jwt_token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                jwt_token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        if not jwt_token:
            return JsonResponse({'error': 'Authentication required'}, status=401)
        
        # Decode JWT token to get student information
        try:
            payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            student_email = payload.get('email')
            student_id = payload.get('_id')
            
            if not student_email or not student_id:
                return JsonResponse({'error': 'Invalid authentication token'}, status=401)
                
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Authentication token expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid authentication token'}, status=401)
        
        # Find student in the database
        student_data_collection = db['users']
        student = student_data_collection.find_one({'email': student_email})
        
        if not student:
            return JsonResponse({'error': 'Student not found'}, status=404)
        
        # Get current datetime
        current_datetime = datetime.now()
        current_date = current_datetime.date()
        
        # Initialize streak values if not present
        current_streak = student.get('login_streak', 0)
        max_streak = student.get('max_login_streak', 0)
        attendance_percentage = student.get('attendance_percentage', 100.0)
        
        # Get account creation date and last login time
        account_creation_date = student.get('created_at')
        last_login = student.get('last_login')
        login_history = student.get('login_history', [])
        
        # Check if user already logged in today to prevent multiple login counts for same day
        already_logged_in_today = False
        if login_history:
            last_login_in_history = login_history[-1]
            last_login_date = last_login_in_history.date() if hasattr(last_login_in_history, 'date') else last_login_in_history
            
            if hasattr(last_login_date, 'year'):  # Make sure it's a date object
                already_logged_in_today = (last_login_date == current_date)
            
        # Debug information
        print(f"Processing attendance for {student['name']}")
        print(f"Current date: {current_date}")
        print(f"Last login: {last_login}")
        print(f"Already logged in today: {already_logged_in_today}")
        
        # Calculate streak based on days between logins
        if last_login:
            # Convert last_login to date object (remove time)
            last_login_date = last_login.date() if hasattr(last_login, 'date') else last_login
            
            days_difference = (current_date - last_login_date).days
            
            if days_difference == 0:
                # Same day login - don't increment streak
                print("Same day login - maintaining streak")
                # No changes to attendance percentage
            elif days_difference == 1:
                # Consecutive day login - increment streak
                print("Consecutive day login - incrementing streak")
                current_streak += 1
                
                # Improve attendance percentage slightly for consecutive logins
                if attendance_percentage < 100.0:
                    attendance_percentage = min(100.0, attendance_percentage + 0.5)
                    print(f"Improving attendance: +0.5% → {attendance_percentage}%")
            else:
                # More than one day gap - reset streak to 1
                print(f"Gap of {days_difference} days - resetting streak to 1")
                current_streak = 1
                
                # Calculate attendance percentage penalty
                # Calculate total days since account creation
                total_days = (current_date - account_creation_date.date()).days + 1
                
                # Get unique login dates (ignoring multiple logins on same day)
                unique_login_dates = set()
                for login_time in login_history:
                    login_date = login_time.date() if hasattr(login_time, 'date') else login_time
                    unique_login_dates.add(login_date)
                
                # Add today's date to unique login dates
                unique_login_dates.add(current_date)
                
                # Calculate attendance percentage as unique login days / total days
                # We start from day after account creation, so total days - 1
                days_expected = max(1, total_days)  # Avoid division by zero
                days_attended = len(unique_login_dates)
                
                # Calculate the new attendance percentage
                new_attendance = (days_attended / days_expected) * 100
                
                # Apply a smoother transition by taking 70% of the new calculation
                # and 30% of the previous percentage to avoid drastic drops
                attendance_percentage = (0.7 * new_attendance) + (0.3 * attendance_percentage)
                
                print(f"Recalculated attendance: {days_attended}/{days_expected} days = {new_attendance:.2f}%")
                print(f"Blended attendance percentage: {attendance_percentage:.2f}%")
        else:
            # First login - start streak at 1 and attendance at 100%
            current_streak = 1
            attendance_percentage = 100.0
            print("First login - setting streak to 1 and attendance to 100%")
        
        # Ensure minimum streak of 1 for active users
        if current_streak == 0:
            current_streak = 1
        
        # Cap attendance percentage between 0 and 100
        attendance_percentage = max(0.0, min(100.0, attendance_percentage))
            
        # Update max streak if current streak is higher
        if current_streak > max_streak:
            max_streak = current_streak
            
        print(f"Final current streak: {current_streak}")
        print(f"Final max streak: {max_streak}")
        print(f"Final attendance percentage: {attendance_percentage:.2f}%")
        
        # Only add login to history if it's the first login of the day
        if not already_logged_in_today:
            login_history.append(current_datetime)
            print("Adding new login to history - first login of the day")
        else:
            print("Not adding login to history - already logged in today")
            
        # Update student document with new streak and attendance information
        student_data_collection.update_one(
            {'_id': student['_id']},
            {
                '$set': {
                    'last_login': current_datetime,
                    'login_streak': current_streak,
                    'max_login_streak': max_streak,
                    'attendance_percentage': round(attendance_percentage, 2),
                    'login_history': login_history
                }
            }
        )
        
        # Return the updated streak and attendance information
        return JsonResponse({
            'success': True,
            'attendance': {
                'current_streak': current_streak,
                'max_streak': max_streak,
                'attendance_percentage': round(attendance_percentage, 2),
                'last_login': current_datetime.isoformat(),
                'login_count': len(login_history)  # This will reflect unique days
            }
        }, status=200)
        
    except Exception as e:
        import traceback
        print(f"Error in student_attendance: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'error': f'Server error: {str(e)}'}, status=500)

@csrf_exempt
def get_student_points_by_event(request, event_id):
    if request.method != "GET":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        # JWT extraction
        jwt_token = request.COOKIES.get('jwt')
        if not jwt_token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                jwt_token = auth_header[7:]

        if not jwt_token:
            return JsonResponse({"error": "Authentication required"}, status=401)

        try:
            payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            student_email = payload.get('email')
            if not student_email:
                return JsonResponse({"error": "Invalid authentication token"}, status=401)
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Authentication token expired"}, status=401)
        except jwt.InvalidTokenError as e:
            return JsonResponse({"error": f"Invalid authentication token: {str(e)}"}, status=401)

        # Check student mapping to event
        mapped_events_collection = db['Mapped_Events']
        mapped_event = mapped_events_collection.find_one({
            "event_id": event_id,
            "assigned_admins": {
                "$elemMatch": {
                    "users": {
                        "$elemMatch": {
                            "email": student_email
                        }
                    }
                }
            }
        })

        if not mapped_event:
            return JsonResponse({
                "error": "You don't have access to this event",
                "message": "This event is not assigned to you."
            }, status=403)

        # Get event details
        event_doc = tasks_collection.find_one({"_id": ObjectId(event_id)})
        if not event_doc:
            return JsonResponse({"error": "Event not found"}, status=404)

        event_name = event_doc.get("event_name", "Unknown Event")
        points_collection = db['Points']
        points_data = points_collection.find_one({"event_id": event_id})

        # === Calculate total points in event (from task collection) ===
        total_event_points = 0
        for level in event_doc.get("levels", []):
            for task in level.get("tasks", []):
                total_event_points += task.get("total_points", 0)

        # Prepare response
        response = {
            "event_id": event_id,
            "event_name": event_name,
            "total_event_points": total_event_points,  # ✅ added this
            "total_points_earned": 0,
            "total_possible_points": 0,
            "completion_percentage": 0,
            "levels": []
        }

        if not points_data:
            return JsonResponse({
                "success": True,
                "student_email": student_email,
                "data": response
            }, status=200)

        # Build levels and tasks structure from event
        for level in event_doc.get("levels", []):
            level_points_possible = 0
            level_tasks = []

            for task in level.get("tasks", []):
                task_points_possible = task.get("total_points", 0)
                level_points_possible += task_points_possible

                task_data = {
                    "task_id": task.get("task_id"),
                    "task_name": task.get("task_name"),
                    "points_earned": 0,
                    "points_possible": task_points_possible,
                    "status": "incomplete",  # default
                    "frequency": task.get("frequency", "Once"),
                    "deadline": task.get("full_deadline"),
                    "completed_percentage": 0,
                    "subtasks": [
                        {
                            "subtask_id": subtask.get("subtask_id"),
                            "subtask_name": subtask.get("name", ""),
                            "points_possible": subtask.get("points", 0),
                            "points_earned": 0,
                            "status": subtask.get("status", "incomplete")
                        }
                        for subtask in task.get("subtasks", [])
                    ]
                }

                level_tasks.append(task_data)

            response["levels"].append({
                "level_id": level.get("level_id"),
                "level_name": level.get("level_name"),
                "points_earned": 0,
                "points_possible": level_points_possible,
                "completed_percentage": 0,
                "tasks": level_tasks
            })

            response["total_possible_points"] += level_points_possible

        # Map student scores
        for admin in points_data.get("assigned_to", []):
            for student in admin.get("marks", []):
                if student.get("student_email") != student_email:
                    continue

                for student_level in student.get("score", []):
                    level_id = student_level.get("level_id")

                    for response_level in response["levels"]:
                        if response_level["level_id"] != level_id:
                            continue

                        level_points = 0

                        for student_task in student_level.get("task", []):
                            task_id = student_task.get("task_id")
                            task_points = student_task.get("points", 0)
                            level_points += task_points

                            for response_task in response_level["tasks"]:
                                if response_task["task_id"] != task_id:
                                    continue

                                response_task["points_earned"] = task_points

                                if response_task["points_possible"] > 0:
                                    response_task["completed_percentage"] = round(
                                        (task_points / response_task["points_possible"]) * 100
                                    )

                                status = student_task.get("status", "incomplete")

                                if status in ["completely_finished", "fully_completed"]:
                                    response_task["status"] = "fully_completed"
                                elif status in ["partially_finished", "partially_completed"]:
                                    response_task["status"] = "partially_completed"
                                else:
                                    response_task["status"] = "incomplete"

                                for student_subtask in student_task.get("sub_task", []):
                                    subtask_id = student_subtask.get("subtask_id")
                                    subtask_points = student_subtask.get("points", 0)
                                    subtask_status = student_subtask.get("status", "incomplete")

                                    for response_subtask in response_task["subtasks"]:
                                        if response_subtask["subtask_id"] == subtask_id:
                                            response_subtask["points_earned"] = subtask_points
                                            response_subtask["status"] = subtask_status
                                            break

                                break  # task matched

                        response_level["points_earned"] = level_points
                        if response_level["points_possible"] > 0:
                            response_level["completed_percentage"] = round(
                                (level_points / response_level["points_possible"]) * 100
                            )

                        response["total_points_earned"] += level_points
                        break  # level matched

        if response["total_possible_points"] > 0:
            response["completion_percentage"] = round(
                (response["total_points_earned"] / response["total_possible_points"]) * 100
            )

        return JsonResponse({
            "success": True,
            "student_email": student_email,
            "data": response
        }, status=200)

    except Exception as e:
        import traceback
        print(f"Error in get_student_points_by_event: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)
    
    
@csrf_exempt
def get_tasks_by_level_id(request, level_id):
    """
    Fetch all tasks for a specific level ID from the events collection
    
    Args:
        request: HTTP request object
        level_id: The unique identifier of the level
        
    Returns:
        JsonResponse containing all tasks in the specified level
    """
    if request.method != "GET":
        return JsonResponse({"error": "Invalid request method"}, status=405)
    
    try:
        # Verify authentication (optional - uncomment if you want to require authentication)
        # auth_header = request.headers.get('Authorization')
        # if not auth_header or not auth_header.startswith('Bearer '):
        #     return JsonResponse({"error": "Authorization header missing or invalid"}, status=401)
        
        # Find event document containing the specified level_id
        event = tasks_collection.find_one(
            {"levels.level_id": level_id},
            {"_id": 1, "event_name": 1, "levels.$": 1}  # Project only matching level
        )
        
        if not event:
            return JsonResponse({"error": f"No level found with ID: {level_id}"}, status=404)
        
        # Extract level data
        level = event.get("levels", [])[0] if event.get("levels") else None
        
        if not level or level.get("level_id") != level_id:
            return JsonResponse({"error": f"Level data not found for ID: {level_id}"}, status=404)
        
        # Format response data
        response_data = {
            "event_id": str(event.get("_id")),
            "event_name": event.get("event_name"),
            "level_id": level.get("level_id"),
            "level_name": level.get("level_name"),
            "total_points": level.get("total_points"),
            "tasks": []
        }
        
        # Format tasks data
        for task in level.get("tasks", []):
            formatted_task = {
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
                "marking_criteria": task.get("marking_criteria"),
                "last_updated": task.get("last_updated"),
                "next_update_due": task.get("next_update_due"),
                "task_status": task.get("task_status"),
                "subtasks": []
            }
            
            # Format subtasks if any
            for subtask in task.get("subtasks", []):
                formatted_subtask = {
                    "subtask_id": subtask.get("subtask_id"),
                    "name": subtask.get("name", ""),
                    "description": subtask.get("description", ""),
                    "points": subtask.get("points", 0),
                    "status": subtask.get("status", "incomplete")
                }
                formatted_task["subtasks"].append(formatted_subtask)
            
            response_data["tasks"].append(formatted_task)
        
        return JsonResponse({
            "message": f"Found {len(response_data['tasks'])} tasks for level {level.get('level_name')}",
            "data": response_data
        }, status=200)
    
    except Exception as e:
        import traceback
        print(f"Error in get_tasks_by_level_id: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)   
    
@csrf_exempt
def student_milestones(request):
    """
    Fetch milestone data for a specific event and authenticated student.
    Calculates milestone stages based on total event points and user's accumulated points.
    """
    if request.method != "POST":
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    try:
        # Get JWT token from cookies or Authorization header
        jwt_token = request.COOKIES.get('jwt')
        if not jwt_token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                jwt_token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        if not jwt_token:
            return JsonResponse({'error': 'Authentication required'}, status=401)
        
        # Decode JWT token
        try:
            payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            student_email = payload.get('email')
            if not student_email:
                return JsonResponse({'error': 'Invalid authentication token'}, status=401)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Authentication token expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid authentication token'}, status=401)
        
        # Get event_id from request body
        data = json.loads(request.body)
        event_id = data.get('event_id')
        if not event_id:
            return JsonResponse({'error': 'Event ID is required'}, status=400)
        
        # Fetch event data
        try:
            event = tasks_collection.find_one({'_id': ObjectId(event_id)})
        except:
            return JsonResponse({'error': 'Invalid event ID format'}, status=400)
        
        if not event:
            return JsonResponse({'error': 'Event not found'}, status=404)
        
        # Calculate total points for the event
        total_points = 0
        for level in event.get("levels", []):
            for task in level.get("tasks", []):
                total_points += task.get("total_points", 0)
        
        # Define milestone stages
        stage_points = total_points / 5  # Divide into 5 equal parts
        milestones = [
            {"label": "Bronze", "required_points": stage_points * 1},
            {"label": "Silver", "required_points": stage_points * 2},
            {"label": "Gold", "required_points": stage_points * 3},
            {"label": "Platinum", "required_points": stage_points * 4},
            {"label": "Elite", "required_points": stage_points * 5}
        ]
        
        # Fetch user's points for this event
        user_points = 0
        points_data = points_collection.find_one({"event_id": event_id})
        if points_data:
            for admin in points_data.get("assigned_to", []):
                for mark in admin.get("marks", []):
                    if mark.get("student_email") == student_email:
                        for level in mark.get("score", []):
                            for task in level.get("task", []):
                                user_points += task.get("points", 0)
                                for subtask in task.get("sub_task", []):
                                    user_points += subtask.get("points", 0)
        
        # Determine completed milestones
        milestone_response = []
        for milestone in milestones:
            milestone_response.append({
                "label": milestone["label"],
                "completed": user_points >= milestone["required_points"],
                "required_points": milestone["required_points"]
            })
        
        return JsonResponse({
            "success": True,
            "event_id": event_id,
            "event_name": event.get("event_name", ""),
            "total_points": total_points,
            "user_points": user_points,
            "milestones": milestone_response
        }, status=200)
    
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format in request body'}, status=400)
    except Exception as e:
        return JsonResponse({'error': f'Server error: {str(e)}'}, status=500)
    
def assign_ranks(leaderboard: list) -> list:
    """
    Assigns 1-based rank to each entry based on sorted total_score (descending).
    """
    for idx, entry in enumerate(leaderboard):
        entry["rank"] = idx + 1
    return leaderboard

@csrf_exempt
def get_leaderboard_data(request):
    if request.method != "POST":
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
        event_id = data.get('event_id')
        if not event_id:
            return JsonResponse({'error': 'Event ID is required'}, status=400)

        # Fetch all collections
        points_data = points_collection.find_one({"event_id": event_id})
        event_data = tasks_collection.find_one({"_id": ObjectId(event_id)})
        mapped_event = mapped_events_collection.find_one({"event_id": event_id})

        # Total possible score
        total_possible_score = 0
        if event_data and "levels" in event_data:
            for level in event_data["levels"]:
                for task in level.get("tasks", []):
                    total_possible_score += task.get("total_points", 0)

        # Get mapped users
        mapped_users = set()
        if mapped_event:
            for admin in mapped_event.get("assigned_admins", []):
                for user in admin.get("users", []):
                    if user.get("email"):
                        mapped_users.add(user["email"])

        # Process points data
        scored_users = {}
        if points_data:
            for admin in points_data.get("assigned_to", []):
                for mark in admin.get("marks", []):
                    email = mark.get("student_email")
                    if not email:
                        continue

                    student_name = mark.get("student_name", email)
                    total_score = 0
                    tests_taken = 0

                    for level in mark.get("score", []):
                        for task in level.get("task", []):
                            task_points = task.get("points", 0)
                            total_score += task_points
                            if task_points > 0:
                                tests_taken += 1

                    student = student_collection.find_one({"email": email}) or {}

                    average_score = total_score / tests_taken if tests_taken > 0 else 0
                    badge = "BRONZE"
                    if total_score >= 1000:
                        badge = "GOLD"
                    elif total_score >= 500:
                        badge = "SILVER"

                    scored_users[email] = {
                        "_id": str(student.get("_id", ObjectId())),
                        "name": student.get("name", student_name),
                        "email": email,
                        "student_id": student.get("student_id", ""),
                        "total_score": total_score,
                        "tests_taken": tests_taken,
                        "average_score": round(average_score, 2),
                        "badge": badge,
                        "level": 1,
                        "status": student.get("status", mark.get("status", "active")),
                        "total_possible_score": total_possible_score
                    }

        # Merge all mapped users with score data
        leaderboard = []
        for email in mapped_users:
            if email in scored_users:
                leaderboard.append(scored_users[email])
            else:
                student = student_collection.find_one({"email": email}) or {}
                leaderboard.append({
                    "_id": str(student.get("_id", ObjectId())),
                    "name": student.get("name", email),
                    "email": email,
                    "student_id": student.get("student_id", ""),
                    "total_score": 0,
                    "tests_taken": 0,
                    "average_score": 0,
                    "badge": "BRONZE",
                    "level": 1,
                    "status": student.get("status", "inactive"),
                    "total_possible_score": total_possible_score
                })

        # Sort and rank
        leaderboard = assign_ranks(sorted(leaderboard, key=lambda x: x["total_score"], reverse=True))

        # Identify current student (if logged in)
        jwt_token = request.COOKIES.get('jwt') or request.headers.get('Authorization', '').replace('Bearer ', '')
        current_student = None
        if jwt_token:
            try:
                payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                student_email = payload.get('email')
                for entry in leaderboard:
                    if entry["email"] == student_email:
                        current_student = {
                            "rank": entry["rank"],
                            "points": entry["total_score"],
                            "total_possible_score": entry["total_possible_score"]
                        }
                        break
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                pass

        return JsonResponse({
            "success": True,
            "overall": leaderboard,
            "total_students": len(leaderboard),
            "current_student": current_student or {"rank": 0, "points": 0, "total_possible_score": total_possible_score}
        }, status=200)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format in request body'}, status=400)
    except Exception as e:
        return JsonResponse({'error': f'Server error: {str(e)}'}, status=500)

        
@csrf_exempt
@require_POST
def get_student_data(request):
    try:
        # Parse the request body
        data = json.loads(request.body)
        token = data.get('token')
        
        if not token:
            return JsonResponse({'error': 'JWT token is required'}, status=400)
        
        # Decode the JWT token
        try:
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid token'}, status=401)
        
        # Extract user information from decoded token
        user_id = decoded_token.get('_id')
        email = decoded_token.get('email')
        roll_no = decoded_token.get('roll_no')
        name = decoded_token.get('name')    
        
        # Query student_collection - try multiple approaches
        student = None
        
        # First try by ObjectId if user_id exists
        if user_id:
            try:
                student = student_collection.find_one({'_id': ObjectId(user_id)})
            except:
                pass
        
        # If not found, try by email
        if not student and email:
            student = student_collection.find_one({'email': email})
        
        # If not found, try by student_id using roll_no
        if not student and roll_no:
            student = student_collection.find_one({'student_id': roll_no})
        
        # If still not found, return error
        if not student:
            return JsonResponse({'error': 'Student not found'}, status=404)
        
        # Check if login should be recorded (once per day)
        current_time = datetime.now()
        current_date = current_time.date()
        last_login = student.get('last_login')
        login_history = student.get('login_history', [])
        login_count_updated = False
        
        # Check if already logged in today
        already_logged_today = False
        
        if last_login:
            last_login_date = last_login.date() if hasattr(last_login, 'date') else last_login
            already_logged_today = (last_login_date == current_date)
        
        # Also check login_history for today's date to be extra sure
        if not already_logged_today and login_history:
            for login_time in reversed(login_history[-5:]):  # Check last 5 entries for efficiency
                login_date = login_time.date() if hasattr(login_time, 'date') else login_time
                if hasattr(login_date, 'year'):  # Ensure it's a date object
                    if login_date == current_date:
                        already_logged_today = True
                        break
        
        # Only update login data if not already logged in today
        if not already_logged_today:
            # Update login count and last login
            login_count = student.get('login_count', 0) + 1
            
            # Add current login to history
            updated_login_history = login_history + [current_time]
            
            # Update the database
            student_collection.update_one(
                {'_id': student['_id']},
                {
                    '$set': {
                        'login_count': login_count, 
                        'last_login': current_time,
                        'login_history': updated_login_history
                    }
                }
            )
            
            # Update the student object for response
            student['login_count'] = login_count
            student['last_login'] = current_time
            student['login_history'] = updated_login_history
            login_count_updated = True
        else:
            # Already logged in today, just update last_login time for session tracking
            # but don't increment count or add to history
            student_collection.update_one(
                {'_id': student['_id']},
                {'$set': {'last_login': current_time}}
            )
            student['last_login'] = current_time
        
        # Remove sensitive fields
        fields_to_remove = ['login_attempts', 'password', 'password_set', 'status']
        for field in fields_to_remove:
            if field in student:
                del student[field]
        
        # Convert ObjectId to string for JSON serialization
        student['_id'] = str(student['_id'])
        
        # Convert datetime objects to ISO format strings
        if 'created_at' in student and student['created_at']:
            student['created_at'] = student['created_at'].isoformat()
        if 'last_login' in student and student['last_login']:
            student['last_login'] = student['last_login'].isoformat()
        if 'login_history' in student and student['login_history']:
            student['login_history'] = [date.isoformat() for date in student['login_history']]
        
        return JsonResponse({
            'success': True,
            'name': student.get('name', ''),
            'student_data': student,
            'login_count_updated': login_count_updated
        }, status=200)
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON in request body'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
       
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from bson import ObjectId
import jwt
from datetime import datetime

# Assuming these are defined elsewhere
# points_collection, tasks_collection, student_collection, JWT_SECRET, JWT_ALGORITHM

@csrf_exempt
def get_leaderboard_by_level(request):
    if request.method != "POST":
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
        event_id = data.get('event_id')
        if not event_id:
            return JsonResponse({'error': 'Event ID is required'}, status=400)

        points_data = points_collection.find_one({"event_id": event_id})
        event = tasks_collection.find_one({"_id": ObjectId(event_id)})
        mapped_event = mapped_events_collection.find_one({"event_id": event_id})

        if not event:
            return JsonResponse({'error': 'Event not found'}, status=404)

        number_of_levels = len(event.get("levels", []))
        level_leaderboards = {f"level_{i+1}": [] for i in range(number_of_levels)}
        overall_leaderboard = []

        # Calculate total possible score
        total_possible_score = 0
        if event and "levels" in event:
            for level in event["levels"]:
                for task in level.get("tasks", []):
                    total_possible_score += task.get("total_points", 0)

        # Collect mapped user emails
        mapped_emails = set()
        if mapped_event:
            for admin in mapped_event.get("assigned_admins", []):
                for user in admin.get("users", []):
                    email = user.get("email")
                    if email:
                        mapped_emails.add(email)

        # Collect scored users
        scored_users = {}
        if points_data:
            for admin in points_data.get("assigned_to", []):
                for mark in admin.get("marks", []):
                    email = mark.get("student_email")
                    if not email or email in scored_users:
                        continue

                    student_name = mark.get("student_name", email)
                    total_score = 0
                    tests_taken = 0
                    level_scores = {f"level_{i+1}": 0 for i in range(number_of_levels)}
                    latest_timestamp = None

                    for level in mark.get("score", []):
                        level_id = level.get("level_id")
                        level_number = next((i + 1 for i, lvl in enumerate(event.get("levels", [])) if lvl.get("level_id") == level_id), None)
                        if level_number is None:
                            continue

                        level_score = 0
                        for task in level.get("task", []):
                            task_points = task.get("points", 0)
                            level_score += task_points
                            if task_points > 0:
                                tests_taken += 1

                            task_timestamp = task.get("last_updated_on") or task.get("points_assigned_on")
                            if task_timestamp:
                                if isinstance(task_timestamp, dict) and '$date' in task_timestamp:
                                    task_time = datetime.fromisoformat(task_timestamp['$date'].replace('Z', '+00:00'))
                                elif isinstance(task_timestamp, datetime):
                                    task_time = task_timestamp
                                else:
                                    continue
                                if not latest_timestamp or (task_time and task_time < latest_timestamp):
                                    latest_timestamp = task_time

                        level_scores[f"level_{level_number}"] = level_score
                        total_score += level_score

                    student = student_collection.find_one({"email": email}) or {}
                    average_score = total_score / tests_taken if tests_taken > 0 else 0

                    badge = "BRONZE"
                    if total_score >= 1000:
                        badge = "GOLD"
                    elif total_score >= 500:
                        badge = "SILVER"

                    entry = {
                        "_id": str(student.get("_id", ObjectId())),
                        "name": student.get("name", student_name),
                        "email": email,
                        "student_id": student.get("student_id", ""),
                        "total_score": total_score,
                        "tests_taken": tests_taken,
                        "average_score": round(average_score, 2),
                        "badge": badge,
                        "level": level_number if level_number else 1,
                        "status": student.get("status", mark.get("status", "active")),
                        "timestamp": latest_timestamp.isoformat() if latest_timestamp else None,
                        "total_possible_score": total_possible_score
                    }

                    scored_users[email] = entry
                    overall_leaderboard.append(entry)
                    for level_key in level_scores:
                        if level_scores[level_key] > 0 or tests_taken > 0:
                            level_entry = {**entry, "total_score": level_scores[level_key]}
                            level_leaderboards[level_key].append(level_entry)

        for email in mapped_emails:
            if email in scored_users:
                continue
            student = student_collection.find_one({"email": email}) or {}
            entry = {
                "_id": str(student.get("_id", ObjectId())),
                "name": student.get("name", email),
                "email": email,
                "student_id": student.get("student_id", ""),
                "total_score": 0,
                "tests_taken": 0,
                "average_score": 0,
                "badge": "BRONZE",
                "level": 1,
                "status": student.get("status", "inactive"),
                "timestamp": None,
                "total_possible_score": total_possible_score
            }
            overall_leaderboard.append(entry)

        def assign_ranks(entries):
            if not entries:
                return entries
            sorted_entries = sorted(
                entries,
                key=lambda x: (-x["total_score"], x["timestamp"] or "9999-12-31T23:59:59.999Z")
            )
            current_rank = 1
            for i, entry in enumerate(sorted_entries):
                if i > 0 and (
                    sorted_entries[i]["total_score"] != sorted_entries[i-1]["total_score"] or
                    sorted_entries[i]["timestamp"] != sorted_entries[i-1]["timestamp"]
                ):
                    current_rank = i + 1
                entry["rank"] = current_rank
            return sorted_entries

        overall_leaderboard = assign_ranks(overall_leaderboard)
        for level_key in level_leaderboards:
            level_leaderboards[level_key] = assign_ranks(level_leaderboards[level_key])

        jwt_token = request.COOKIES.get('jwt') or request.headers.get('Authorization', '').replace('Bearer ', '')
        current_student = None
        if jwt_token:
            try:
                payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                student_email = payload.get('email')
                for entry in overall_leaderboard:
                    if entry["email"] == student_email:
                        current_student = {
                            "rank": entry["rank"],
                            "points": entry["total_score"],
                            "student_id": entry["student_id"],
                            "timestamp": entry["timestamp"],
                            "total_possible_score": entry["total_possible_score"]
                        }
                        break
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                pass

        return JsonResponse({
            "success": True,
            "overall": overall_leaderboard,
            "levels": level_leaderboards,
            "total_students": len(overall_leaderboard),
            "current_student": current_student or {"rank": 0, "points": 0, "student_id": "", "timestamp": None, "total_possible_score": total_possible_score}
        }, status=200)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format in request body'}, status=400)
    except Exception as e:
        import traceback
        print(f"Error in get_leaderboard_by_level: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'error': f'Server error: {str(e)}'}, status=500)

@csrf_exempt
def total_points_of_user(request):
    if request.method != "GET":
        return JsonResponse({"error": "Only GET method allowed"}, status=405)

    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({"error": "Authorization header missing or invalid"}, status=401)

        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        student_email = payload.get('email')
        student_name = payload.get('name')
        print(f"Decoded JWT payload: {payload}")

        if not student_email or not student_name:
            return JsonResponse({"error": "Invalid token payload"}, status=400)

        result = {
            "name": student_name,
            "email": student_email,
            "task_points_from": {},
            "total_user_points": 0,
            "total_tasks_allocated": 0,
            "total_tasks_completed": 0,
            "task_progression": 0
        }

        for event in points_collection.find():
            event_name = event.get("event_name", "Unknown Event")

            for admin in event.get("assigned_to", []):
                for mark in admin.get("marks", []):
                    if (
                        mark.get("student_email") == student_email and
                        mark.get("student_name") == student_name
                    ):
                        for score in mark.get("score", []):
                            level_name = score.get("level_name", "Unnamed Level")

                            for task in score.get("task", []):
                                task_name = task.get("task_name") or "Unnamed Task"
                                points = task.get("points", 0)
                                status = task.get("status", "").strip().lower()

                                # Count every task (allocated)
                                result["total_tasks_allocated"] += 1

                                # Count completed task only if status is "completely_finished"
                                if status == "completely_finished":
                                    result["total_tasks_completed"] += 1

                                # Build nested dict if missing
                                if event_name not in result["task_points_from"]:
                                    result["task_points_from"][event_name] = {}
                                if level_name not in result["task_points_from"][event_name]:
                                    result["task_points_from"][event_name][level_name] = {}

                                # Store both points and status per task
                                result["task_points_from"][event_name][level_name][task_name] = {
                                    "points": points,
                                    "status": status
                                }

                                # Sum up total user points
                                result["total_user_points"] += points

        # Calculate task progression
        if result["total_tasks_allocated"] > 0:
            result["task_progression"] = round(
                result["total_tasks_completed"] / result["total_tasks_allocated"], 2
            )

        return JsonResponse(result, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid token'}, status=401)
    except Exception as e:
        return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)
    

@csrf_exempt
def students_point_by_eventid(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method. Use POST."}, status=405)

    try:
        payload = json.loads(request.body)
        event_id = payload.get("event_id")
        level_id = payload.get("level_id")
        token = payload.get("jwt")

        if not (event_id and level_id and token):
            return JsonResponse({"error": "Missing required fields"}, status=400)

        # Decode JWT
        try:
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            student_email = decoded_token.get("email")
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "JWT token has expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid JWT token"}, status=401)

        if not student_email:
            return JsonResponse({"error": "Invalid token. Email not found."}, status=400)

        # Step 1: Fetch student score from points_collection
        points_doc = points_collection.find_one({"event_id": event_id})
        if not points_doc:
            return JsonResponse({"error": "Event not found in points_collection"}, status=404)

        student_scores = []
        student_name = None
        for assignment in points_doc.get("assigned_to", []):
            for mark in assignment.get("marks", []):
                if mark.get("student_email") == student_email:
                    student_name = mark.get("student_name")
                    for level in mark.get("score", []):
                        if level.get("level_id") == level_id:
                            student_scores = level.get("task", [])
                            break
                    break

        if not student_scores:
            return JsonResponse({"error": "No task scores found for the student at this level"}, status=404)

        # Step 2: Fetch level data from tasks_collection
        task_doc = tasks_collection.find_one({"_id": ObjectId(event_id)})
        if not task_doc:
            return JsonResponse({"error": "Event not found in tasks_collection"}, status=404)

        task_schema_map = {}
        for level in task_doc.get("levels", []):
            if level.get("level_id") == level_id:
                for task in level.get("tasks", []):
                    subtask_map = {
                        sub["subtask_id"]: {
                            "name": sub.get("name", "Unknown Subtask"),
                            "points": sub.get("points", 0)
                        }
                        for sub in task.get("subtasks", [])
                    }
                    task_schema_map[task["task_id"]] = {
                        "task_name": task.get("task_name", "Unknown Task"),
                        "total_points": task.get("total_points", 0),
                        "subtasks": subtask_map
                    }

        # Step 3: Build final response
        task_results = []
        for score in student_scores:
            task_id = score.get("task_id")
            earned = score.get("points", 0)
            task_info = task_schema_map.get(task_id, {})

            total = task_info.get("total_points", 0)
            task_name = task_info.get("task_name", "Unknown Task")
            progress = round((earned / total) * 100, 2) if total > 0 else 0.0

            # Handle subtasks (optional)
            subtasks_output = []
            for subtask in score.get("sub_task", []):
                sub_id = subtask.get("subtask_id")
                sub_name = subtask.get("subtask_name")
                earned_sub_points = subtask.get("points", 0)
                schema_sub = task_info.get("subtasks", {}).get(sub_id, {})
                total_sub_points = schema_sub.get("points", 0)
                sub_progress = round((earned_sub_points / total_sub_points) * 100, 2) if total_sub_points > 0 else 0.0

                subtasks_output.append({
                    "subtask_id": sub_id,
                    "subtask_name": sub_name,
                    "earned_points": earned_sub_points,
                    "total_points": total_sub_points,
                    "progress_percent": sub_progress
                })

            task_results.append({
                "task_id": task_id,
                "task_name": task_name,
                "earned_points": earned,
                "total_points": total,
                "progress_percent": progress,
                "subtasks": subtasks_output  # Optional
            })

        return JsonResponse({
            "event_id": event_id,
            "student_email": student_email,
            "student_name": student_name,
            "level_id": level_id,
            "tasks": task_results
        }, status=200)

    except Exception as e:
        return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)
    


@csrf_exempt
def validate_reset_token_for_student(request):
    """
    Endpoint to validate JWT password reset token.
    Expects token and email as query parameters.
    Returns whether the token is valid or expired.
    """
    if request.method != "GET":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    try:
        token = request.GET.get('token')
        email = request.GET.get('email')

        if not token or not email:
            return JsonResponse({"error": "Token and email are required"}, status=400)

        # Decode and verify JWT token
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            token_email = payload.get('email')
            if token_email != email:
                return JsonResponse({
                    "error": "Invalid token: email mismatch",
                    "redirect": "/forgot-password"
                }, status=400)
        except jwt.ExpiredSignatureError:
            return JsonResponse({
                "error": "Token has expired",
                "redirect": "/forgot-password"
            }, status=400)
        except jwt.InvalidTokenError:
            return JsonResponse({
                "error": "Invalid token",
                "redirect": "/forgot-password"
            }, status=400)

        # Check if token exists in database and is not expired
        student = student_collection.find_one({
            'email': email,
            'reset_token': token,
            'reset_token_expiry': {'$gt': datetime.now()}
        })

        if not student:
            return JsonResponse({
                "error": "Invalid or expired token",
                "redirect": "/forgot-password"
            }, status=400)

        return JsonResponse({
            "message": "Token is valid",
            "email": email
        }, status=200)

    except Exception as e:
        return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)

@csrf_exempt
def student_daily_points_by_event(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Only POST method allowed"}, status=405)
    
    try:
        data = json.loads(request.body)
        token = data.get('jwt')
        event_id = data.get('event_id')

        if not token or not event_id:
            return JsonResponse({"error": "Missing jwt or event_id"}, status=400)

        # decode token
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            student_email = payload.get('email')
            student_name = payload.get('name')
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)

        if not student_email or not student_name:
            return JsonResponse({"error": "Invalid token payload"}, status=400)

        # find matching points document
        points_doc = points_collection.find_one({"event_id": event_id})
        if not points_doc:
            return JsonResponse({"error": "Event not found"}, status=404)

        # build date -> total points map
        daily_points = {}

        for admin in points_doc.get('assigned_to', []):
            for mark in admin.get('marks', []):
                if mark.get('student_email') == student_email and mark.get('student_name') == student_name:
                    for level in mark.get('score', []):
                        for task in level.get('task', []):
                            # handle task points
                            task_points = task.get('points', 0)
                            task_date = task.get('points_assigned_on')
                            if task_date:
                                if isinstance(task_date, datetime):
                                    date_str = task_date.strftime('%Y-%m-%d')
                                else:
                                    try:
                                        parsed = datetime.strptime(task_date, "%Y-%m-%dT%H:%M:%S.%f%z")
                                        date_str = parsed.strftime('%Y-%m-%d')
                                    except ValueError:
                                        parsed = datetime.strptime(task_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                                        date_str = parsed.strftime('%Y-%m-%d')
                                daily_points[date_str] = daily_points.get(date_str, 0) + task_points

                            # handle sub_task points
                            for sub in task.get('sub_task', []):
                                sub_points = sub.get('points', 0)
                                sub_date = sub.get('points_assigned_on')
                                if sub_date:
                                    if isinstance(sub_date, datetime):
                                        date_str = sub_date.strftime('%Y-%m-%d')
                                    else:
                                        try:
                                            parsed = datetime.strptime(sub_date, "%Y-%m-%dT%H:%M:%S.%f%z")
                                            date_str = parsed.strftime('%Y-%m-%d')
                                        except ValueError:
                                            parsed = datetime.strptime(sub_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                                            date_str = parsed.strftime('%Y-%m-%d')
                                    daily_points[date_str] = daily_points.get(date_str, 0) + sub_points

        # build sorted result list
        result = [
            {"date": date, "total_points": total}
            for date, total in sorted(daily_points.items())
        ]

        return JsonResponse({
            "student_email": student_email,
            "student_name": student_name,
            "event_id": event_id,
            "daily_points": result
        }, status=200)

    except Exception as e:
        return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)
@csrf_exempt
def student_recent_tasks_by_event(request):
    """
    Fetch recent tasks in an event, based on logged-in student info and event_id.
    Now includes total points grouped by event for the student,
    and only lists incomplete tasks.
    """
    if request.method != 'POST':
        return JsonResponse({"error": "Only POST method allowed"}, status=405)

    try:
        data = json.loads(request.body)
        token = data.get('jwt')
        event_id = data.get('event_id')

        if not token or not event_id:
            return JsonResponse({"error": "Missing jwt or event_id"}, status=400)

        # Decode JWT
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            student_email = payload.get('email')
            student_name = payload.get('name')
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)

        if not student_email or not student_name:
            return JsonResponse({"error": "Invalid token payload"}, status=400)

        # Find the event in the events_collection
        event_doc = tasks_collection.find_one({"_id": ObjectId(event_id)})
        if not event_doc:
            return JsonResponse({"error": "Event not found"}, status=404)

        # === Fetch task completion status from Points collection ===
        completed_task_ids = set()

        points_data = db['Points'].find_one({"event_id": event_id})
        if points_data:
            for admin in points_data.get("assigned_to", []):
                for student in admin.get("marks", []):
                    if student.get("student_email") == student_email:
                        for level in student.get("score", []):
                            for task in level.get("task", []):
                                if task.get("status") == "completely_finished":
                                    completed_task_ids.add(task.get("task_id"))

        # === Collect tasks data ===
        recent_tasks = []
        event_name = event_doc.get("event_name")
        start_date = event_doc.get("start_date")
        end_date = event_doc.get("end_date")

        for level in event_doc.get("levels", []):
            level_id = level.get("level_id")
            level_name = level.get("level_name")

            for task in level.get("tasks", []):
                task_id = task.get("task_id")

                # ✅ Skip completed tasks
                if task_id in completed_task_ids:
                    continue

                task_obj = {
                    "task_id": task_id,
                    "task_name": task.get("task_name"),
                    "description": task.get("description"),
                    "total_points": task.get("total_points"),
                    "deadline": task.get("deadline"),
                    "deadline_time": task.get("deadline_time"),
                    "full_deadline": task.get("full_deadline"),
                    "frequency": task.get("frequency"),
                    "start_date": task.get("start_date"),
                    "end_date": task.get("end_date"),
                    "task_status": task.get("task_status"),
                    "created_at": task.get("created_at").isoformat() if task.get("created_at") else None,
                    "updated_at": task.get("updated_at").isoformat() if task.get("updated_at") else None,
                    "level_id": level_id,
                    "level_name": level_name,
                    "subtasks": []
                }

                for sub in task.get("subtasks", []):
                    subtask_obj = {
                        "subtask_id": sub.get("subtask_id"),
                        "name": sub.get("name"),
                        "description": sub.get("description"),
                        "points": sub.get("points"),
                        "deadline": sub.get("deadline"),
                        "deadline_time": sub.get("deadline_time"),
                        "full_deadline": sub.get("full_deadline"),
                        "status": sub.get("status"),
                        "completion_history": sub.get("completion_history", [])
                    }
                    task_obj["subtasks"].append(subtask_obj)

                recent_tasks.append(task_obj)

        # Sort tasks by created_at descending
        recent_tasks.sort(key=lambda x: x["created_at"] or '', reverse=True)

        # === Points Summary ===
        total_points_earned = 0
        total_possible_points = 0

        for level in event_doc.get("levels", []):
            for task in level.get("tasks", []):
                total_possible_points += task.get("total_points", 0)

        if points_data:
            for admin in points_data.get("assigned_to", []):
                for student in admin.get("marks", []):
                    if student.get("student_email") == student_email:
                        for score in student.get("score", []):
                            for task in score.get("task", []):
                                total_points_earned += task.get("points", 0)

        return JsonResponse({
            "student_email": student_email,
            "student_name": student_name,
            "event_id": event_id,
            "event_name": event_name,
            "start_date": start_date,
            "end_date": end_date,
            "total_points_summary": {
                "earned": total_points_earned,
                "possible": total_possible_points,
                "completion_percentage": round((total_points_earned / total_possible_points) * 100) if total_possible_points else 0
            },
            "recent_tasks": recent_tasks
        }, status=200)

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)

@csrf_exempt
def student_events_list(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Invalid request method."}, status=405)

    try:
        data = json.loads(request.body)
        token = data.get('jwt')

        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        student_email = payload.get('email')
        student_name = payload.get('name')

    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "Invalid token"}, status=401)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    try:
        mapped_events = mapped_events_collection.find({
            "assigned_admins.users.email": student_email
        })

        recent_events = []

        for event in mapped_events:
            event_id = str(event["event_id"])
            event_name = event["event_name"]

            task_doc = tasks_collection.find_one({"_id": ObjectId(event_id)})
            if not task_doc:
                continue

            all_task_ids = []
            level_details = []

            # Step 1: Collect all task IDs and structure levels
            for level in task_doc.get("levels", []):
                level_id = level.get("level_id")
                level_name = level.get("level_name")
                tasks = []

                for task in level.get("tasks", []):
                    task_id = task.get("task_id")
                    task_name = task.get("task_name")
                    subtasks = task.get("subtasks", [])

                    all_task_ids.append(task_id)

                    # Prepare subtask structure
                    subtask_details = []
                    for sub in subtasks:
                        subtask_details.append({
                            "subtask_id": sub.get("subtask_id"),
                            "name": sub.get("name"),
                            "description": sub.get("description"),
                            "points": sub.get("points"),
                            "deadline": sub.get("deadline"),
                            "deadline_time": sub.get("deadline_time"),
                            "full_deadline": sub.get("full_deadline"),
                            "status": "incomplete",
                            "completion_history": sub.get("completion_history", [])
                        })

                    tasks.append({
                        "task_id": task_id,
                        "task_name": task_name,
                        "status": "incomplete",  # Default status
                        "subtasks": subtask_details
                    })

                level_details.append({
                    "level_id": level_id,
                    "level_name": level_name,
                    "tasks": tasks
                })

            # Step 2: Get completion status from points_collection
            points_doc = points_collection.find_one({"event_id": event_id})
            completed_task_ids = set()
            task_status_map = {}
            subtask_status_map = {}

            if points_doc:
                for admin in points_doc.get("assigned_to", []):
                    for mark in admin.get("marks", []):
                        if mark.get("student_email") == student_email:
                            for score in mark.get("score", []):
                                for task in score.get("task", []):
                                    task_id = task.get("task_id")
                                    subtasks = task.get("sub_task", [])

                                    if subtasks:
                                        # Process subtasks
                                        subtask_statuses = []
                                        subtask_status_dict = {}
                                        
                                        for subtask in subtasks:
                                            subtask_id = subtask.get("subtask_id")
                                            status = subtask.get("status", "incomplete")
                                            subtask_statuses.append(status)
                                            subtask_status_dict[subtask_id] = status
                                        
                                        # Store subtask statuses for this task
                                        if task_id not in subtask_status_map:
                                            subtask_status_map[task_id] = {}
                                        subtask_status_map[task_id].update(subtask_status_dict)

                                        # Determine task status based on subtask statuses
                                        completely_finished_count = subtask_statuses.count("completely_finished")
                                        partially_finished_count = subtask_statuses.count("partially_finished")
                                        incomplete_count = subtask_statuses.count("incomplete")
                                        
                                        if completely_finished_count == len(subtask_statuses):
                                            # All subtasks are completely finished
                                            task_status_map[task_id] = "completely_finished"
                                            completed_task_ids.add(task_id)
                                        elif completely_finished_count > 0 or partially_finished_count > 0:
                                            # At least one subtask is partially or completely finished
                                            task_status_map[task_id] = "partially_finished"
                                        else:
                                            # All subtasks are incomplete
                                            task_status_map[task_id] = "incomplete"
                                    else:
                                        # Task without subtasks
                                        status = task.get("status", "incomplete")
                                        task_status_map[task_id] = status
                                        if status == "completely_finished":
                                            completed_task_ids.add(task_id)

            # Step 3: Update level_details with status
            for level in level_details:
                for task in level["tasks"]:
                    task_id = task["task_id"]
                    # Update task status
                    task["status"] = task_status_map.get(task_id, "incomplete")

                    # Update subtask statuses
                    if task_id in subtask_status_map:
                        for subtask in task["subtasks"]:
                            subtask_id = subtask["subtask_id"]
                            subtask["status"] = subtask_status_map[task_id].get(subtask_id, "incomplete")

            # Step 4: Final check — if not all tasks completed, it's a recent event
            if not all(task_id in completed_task_ids for task_id in all_task_ids):
                recent_events.append({
                    "event_id": event_id,
                    "event_name": event_name,
                    "student_email": student_email,
                    "student_name": student_name,
                    "task_total": len(all_task_ids),
                    "task_completed": len(completed_task_ids),
                    "levels": level_details
                })

        return JsonResponse({"recent_events": recent_events}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    

@csrf_exempt
def get_student_levels_progress(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method allowed'}, status=405)

    try:
        data = json.loads(request.body)
        token = data.get('jwt')
        event_id = data.get('event_id')

        if not token or not event_id:
            return JsonResponse({'error': 'JWT token and event_id are required'}, status=400)

        # Decode JWT
        try:
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            student_email = decoded_token.get("email")
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'JWT token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid JWT token'}, status=401)

        if not student_email:
            return JsonResponse({'error': 'Invalid token. Email not found.'}, status=400)

        # Check if mapped
        mapping_doc = mapped_events_collection.find_one({
            "assigned_admins.users.email": student_email,
            "event_id": event_id
        })

        if not mapping_doc:
            return JsonResponse({'error': 'This event is not mapped to the student'}, status=404)

        # Get event details
        try:
            obj_id = ObjectId(event_id)
        except Exception as e:
            return JsonResponse({'error': f'Invalid event_id: {str(e)}'}, status=400)

        event = tasks_collection.find_one({'_id': obj_id})
        if not event:
            return JsonResponse({'error': 'Event not found in task collection'}, status=404)

        event_name = event.get('event_name')
        levels = event.get('levels', [])
        created_at = event.get('created_at')
        updated_at = event.get('updated_at')

        # Total event allocated points
        total_event_allocated_points = sum(level.get('total_points', 0) for level in levels)

        # Get student points
        points_doc = points_collection.find_one({'event_id': event_id})
        student_marks = None

        if points_doc:
            for admin in points_doc.get('assigned_to', []):
                for mark in admin.get('marks', []):
                    if mark.get('student_email') == student_email:
                        student_marks = mark
                        break
                if student_marks:
                    break

        level_data = []
        total_event_points = 0

        for level in levels:
            level_id = level.get('level_id')
            level_name = level.get('level_name')
            total_level_points = level.get('total_points', 0)

            # Create task schema lookup
            task_schema_map = {t['task_id']: t for t in level.get('tasks', [])}

            # Find student score for this level
            student_level_score = None
            if student_marks:
                student_level_score = next(
                    (s for s in student_marks.get('score', []) if s.get('level_id') == level_id), None
                )

            tasks_output = []
            level_points = 0

            if student_level_score:
                for student_task in student_level_score.get('task', []):
                    task_id = student_task.get('task_id')
                    task_name = student_task.get('task_name')
                    schema_task = task_schema_map.get(task_id, {})
                    task_total_points = schema_task.get('total_points', 0)
                    subtask_schema_map = {
                        st['subtask_id']: st for st in schema_task.get('subtasks', [])
                    }

                    task_points = 0
                    subtasks_output = []
                    sub_tasks = student_task.get('sub_task', [])

                    if sub_tasks:
                        for subtask in sub_tasks:
                            subtask_id = subtask.get('subtask_id')
                            subtask_points = subtask.get('points', 0)
                            task_points += subtask_points
                            schema_sub = subtask_schema_map.get(subtask_id, {})
                            subtasks_output.append({
                                'subtask_id': subtask_id,
                                'subtask_name': subtask.get('subtask_name'),
                                'points': subtask_points,
                                'status': subtask.get('status'),
                                'subtask_total_points': schema_sub.get('points', 0)
                            })
                    else:
                        # No subtasks → take task-level points directly
                        task_points = student_task.get('points', 0)

                    tasks_output.append({
                        'task_id': task_id,
                        'task_name': task_name,
                        'points': task_points,
                        'task_total_points': task_total_points,
                        'subtasks': subtasks_output
                    })

                    level_points += task_points

            level_data.append({
                'level_id': level_id,
                'level_name': level_name,
                'points': level_points,
                'total_level_points': total_level_points,
                'tasks': tasks_output
            })

            total_event_points += level_points

        return JsonResponse({
            'success': True,
            'student_email': student_email,
            'event_id': event_id,
            'event_name': event_name,
            'total_points': total_event_points,
            'total_event_allocated_points': total_event_allocated_points,
            'created_at': created_at.isoformat() if isinstance(created_at, datetime) else str(created_at),
            'updated_at': updated_at.isoformat() if isinstance(updated_at, datetime) else str(updated_at),
            'levels': level_data
        }, status=200)

    except Exception as e:
        return JsonResponse({'error': f'Server error: {str(e)}'}, status=500)