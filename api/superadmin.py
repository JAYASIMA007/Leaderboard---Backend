import json
from datetime import datetime, timedelta,timezone
from django.http import JsonResponse
from django.contrib.auth.hashers import check_password, make_password
import jwt
from pymongo import MongoClient
from bson import ObjectId
import os
import uuid
from django.views.decorators.csrf import csrf_exempt
from dotenv import load_dotenv
import re
import os
import json
import re
import uuid
from datetime import datetime
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from dotenv import load_dotenv
from bson import ObjectId
from django.core.mail import send_mail

# Constants
JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'

# Database connection
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client['Leaderboard']
superadmin_collection = db["superadmin"]
student_data_collection = db["users"]
admin_collection = db["admin"]
mapped_events_collection = db['Mapped_Events']
tasks_collection = db["events"]
points_collection = db['Points']

def generate_tokens(superadmin_user, name):
    """Generates JWT tokens for superadmin authentication."""
    payload = {
        'superadmin_user': str(superadmin_user),
        'name': name,
        'role': 'superadmin',
        "exp": datetime.utcnow() + timedelta(days=1),
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {'jwt': token}

def generate_setup_token(admin_id):
    payload = {
        "admin_id": str(admin_id),
        "exp": datetime.utcnow() + timedelta(hours=1),  # Token valid for 1 hour
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def check_account_status(email):
    """Check if account is deactivated."""
    superadmin = superadmin_collection.find_one({'email': email})
    if not superadmin:
        return False
    return superadmin.get('status') == 'Inactive'

def reset_login_attempts(email):
    """Reset login attempts for a given email."""
    superadmin_collection.update_one(
        {'email': email},
        {'$set': {'login_attempts': 0}}
    )

def superadmin_login(email, password):
    """Authenticates a superadmin user and generates a JWT token."""
    try:
        print(client)
        superadmin_user = superadmin_collection.find_one({'email': email})

        if not superadmin_user:
            return {'error': 'Invalid email or password'}, 401

        if check_account_status(email):
            return {'error': 'Account has been deactivated due to too many failed login attempts. Contact the administrator.'}, 403

        if not check_password(password, superadmin_user['password']):
            print("❌ Password mismatch.")
            return {'error': 'Invalid password'}, 401

        reset_login_attempts(email)
        token = generate_tokens(superadmin_user['_id'], superadmin_user['name'])

        superadmin_collection.update_one(
            {'_id': superadmin_user['_id']},
            {'$set': {'last_login': datetime.now()}}
        )

        return {
            'message': 'Logged in successfully',
            'jwt': token['jwt'],
            'last_login': datetime.now(),
            'email': email
        }, 200

    except Exception as e:
        return {'error': str(e)}, 500

@csrf_exempt
def superadmin_login_view(request):
    if request.method == 'POST':
        try:
            # Parse request data
            MONGO_URI = os.getenv("MONGO_URI")
            print(MONGO_URI)
            client = MongoClient(MONGO_URI)
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')


            # Check if email exists in the collection
            superadmin_user = superadmin_collection.find_one({'email': email})
            if not superadmin_user:
                return JsonResponse({'error': 'Invalid email or password'}, status=401)

            # Validate password
            if not check_password(password, superadmin_user.get('password')):
                return JsonResponse({'error': 'Invalid email or password'}, status=401)

            # Generate token and update last login
            token = generate_tokens(superadmin_user['_id'], superadmin_user['name'])
            superadmin_collection.update_one(
                {'_id': superadmin_user['_id']},
                {'$set': {'last_login': datetime.now()}}
            )

            # Return success response
            return JsonResponse({
                'message': 'Logged in successfully',
                'jwt': token['jwt'],
                'last_login': datetime.now(),
                'email': email
            }, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

def get_admin_details():
    try:
        admins = admin_collection.find(
            {'status': 'Active'},
            {'_id': 0, 'name': 1, 'email': 1, 'Admin_ID': 1, 'status': 1}  # Include 'status' field
        )
        return list(admins)
    except Exception as e:
        return None

@csrf_exempt
def get_admins(request):
    if request.method == 'GET':
        try:
            admins = get_admin_details()
            if admins is None:
                return JsonResponse({'error': 'Failed to fetch admin details'}, status=500)
            return JsonResponse(admins, safe=False, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)


# @csrf_exempt
# def create_task(request):
#     if request.method == 'POST':
#         try:
#             # MongoDB connection setup
#             tasks_collection = db['events']
#             admins_collection = db['admin']
#             students_collection = db['users']
#             mapped_events_collection = db['Mapped_Events']

#             # Parse request data
#             try:
#                 data = json.loads(request.body) if request.content_type == 'application/json' else request.POST.dict()
#             except json.JSONDecodeError:
#                 return JsonResponse({'error': 'Invalid JSON format'}, status=400)

#             # Validate required fields
#             required_fields = ['event_name', 'levels', 'assigned_to']
#             if not all(field in data for field in required_fields):
#                 return JsonResponse({'error': 'Missing required fields: event_name, levels, assigned_to'}, status=400)
            
#             # Validate event_name
#             event_name = data['event_name']
#             if not isinstance(event_name, str) or not event_name.strip():
#                 return JsonResponse({'error': 'Event name must be a non-empty string'}, status=400)
#             if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', event_name):
#                 return JsonResponse({'error': 'Event name contains invalid characters'}, status=400)
#             if len(event_name.strip()) > 100:
#                 return JsonResponse({'error': 'Event name exceeds 100 characters'}, status=400)
#             event_name = event_name.strip()

#             # Validate assigned_to
#             assigned_to = data['assigned_to']
#             if not isinstance(assigned_to, list) or not assigned_to:
#                 return JsonResponse({'error': 'Assigned_to must be a non-empty list of admin names or IDs'}, status=400)

#             # Validate admins and collect admin details
#             admin_ids = []
#             assigned_admins = []
#             for admin_identifier in assigned_to:
#                 # Try finding admin by Admin_ID first, then by name
#                 admin = admins_collection.find_one({'Admin_ID': admin_identifier, 'status': 'Active'})
#                 if not admin:
#                     admin = admins_collection.find_one({'name': admin_identifier, 'status': 'Active'})
#                 if not admin:
#                     return JsonResponse({'error': f'Invalid or inactive admin: {admin_identifier}'}, status=400)
#                 admin_id = admin['Admin_ID']
#                 admin_name = admin['name']
#                 admin_ids.append(admin_id)

#                 # Fetch students for this admin
#                 students = students_collection.find(
#                     {'admin_id': admin_id},
#                     {'_id': 0, 'name': 1, 'roll_no': 1, 'email': 1}
#                 )
#                 seen_roll_nos = set()
#                 admin_students = []
#                 for student in students:
#                     if not all(key in student for key in ['name', 'roll_no']):
#                         continue  # Skip invalid student records
#                     if student['roll_no'] not in seen_roll_nos:
#                         admin_students.append({
#                             'name': student['name'],
#                             'roll_no': student['roll_no'],
#                             'email': student.get('email', '')
#                         })
#                         seen_roll_nos.add(student['roll_no'])       
                
#                 assigned_admins.append({
#                     'admin_id': admin_id,
#                     'name': admin_name,
#                     'students': admin_students
#                 })
                
#                 if not admin_students:
#                     print(f"No students found for admin_id: {admin_id}")

#             # Validate levels structure
#             levels = data['levels']
#             if not isinstance(levels, list) or not levels:
#                 return JsonResponse({'error': 'Levels must be a non-empty list'}, status=400)
#             if len(levels) > 50:
#                 return JsonResponse({'error': 'Too many levels (max 50)'}, status=400)

#             # Check for duplicate level names
#             level_names = [level['level_name'].strip() for level in levels]
#             if len(set(level_names)) != len(level_names):
#                 return JsonResponse({'error': 'Level names must be unique within the event'}, status=400)

#             # Process each level
#             for level_index, level in enumerate(levels):
#                 if not isinstance(level, dict) or not all(key in level for key in ['level_name', 'tasks']):
#                     return JsonResponse({'error': f'Level {level_index + 1} must have level_name and tasks'}, status=400)
#                 level_name = level['level_name'].strip()
#                 if not level_name:
#                     return JsonResponse({'error': f'Level {level_index + 1} name cannot be empty or only whitespace'}, status=400)
#                 if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', level_name):
#                     return JsonResponse({'error': f'Level {level_index + 1} name contains invalid characters'}, status=400)
#                 if len(level_name) > 100:
#                     return JsonResponse({'error': f'Level {level_index + 1} name exceeds 100 characters'}, status=400)

#                 tasks = level['tasks']
#                 if not isinstance(tasks, list) or not tasks:
#                     return JsonResponse({'error': f'Tasks must be a non-empty list for level {level_index + 1}'}, status=400)
#                 if len(tasks) > 100:
#                     return JsonResponse({'error': f'Too many tasks in level {level_index + 1} (max 100)'}, status=400)

#                 # Check for duplicate task names within the level
#                 task_names = [task['task_name'].strip() for task in tasks]
#                 if len(set(task_names)) != len(task_names):
#                     return JsonResponse({'error': f'Task names must be unique within level {level_index + 1}'}, status=400)

#                 # Process each task within the level
#                 for task_index, task in enumerate(tasks):
#                     task_required_fields = ['task_name', 'description', 'points', 'start_date', 'end_date', 'marking_criteria']
#                     if not all(field in task for field in task_required_fields):
#                         return JsonResponse({'error': f'Missing required task fields in task {task_index + 1} of level {level_index + 1}: task_name, description, points, start_date, end_date, marking_criteria'}, status=400)

#                     task_name = task['task_name'].strip()
#                     description = task['description'].strip()
#                     if not task_name:
#                         return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} name cannot be empty or only whitespace'}, status=400)
#                     if not description:
#                         return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} description cannot be empty or only whitespace'}, status=400)
#                     if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', task_name):
#                         return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} name contains invalid characters'}, status=400)
#                     if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', description):
#                         return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} description contains invalid characters'}, status=400)
#                     if len(task_name) > 100:
#                         return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} name exceeds 100 characters'}, status=400)
#                     if len(description) > 500:
#                         return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} description exceeds 500 characters'}, status=400)
#                     if not isinstance(task['points'], (int, float)) or task['points'] <= 0:
#                         return JsonResponse({'error': 'Task points must be a positive number'}, status=400)

#                     # Validate dates
#                     try:
#                         start_date = datetime.strptime(task['start_date'], '%Y-%m-%d')
#                         if start_date.date() < datetime.now().date():
#                             return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} start_date cannot be in the past'}, status=400)
#                         end_date = datetime.strptime(task['end_date'], '%Y-%m-%d')
#                         if end_date.date() <= start_date.date():
#                             return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} end_date must be after start_date'}, status=400)
#                     except ValueError:
#                         return JsonResponse({'error': f'Invalid date format in task {task_index + 1} of level {level_index + 1}. Use YYYY-MM-DD'}, status=400)

#                     # Validate deadline_time (optional)
#                     deadline_time = task.get('deadline_time')
#                     if deadline_time:
#                         try:
#                             datetime.strptime(deadline_time, '%H:%M')
#                         except ValueError:
#                             return JsonResponse({'error': 'Invalid deadline_time format. Use HH:MM (24-hour format)'}, status=400)
#                     else:
#                         deadline_time = '23:59'

#                     # Create full deadline datetime by combining date and time
#                     full_deadline = f"{task['end_date']}T{deadline_time}:00"
                    
#                     # Validate task_type (optional field)
#                     task_type = task.get('task_type', 'Once')
#                     if task_type not in ['Once', 'Daily', 'Weekly']:
#                         return JsonResponse({'error': 'Task type must be "Once", "Daily", or "Weekly"'}, status=400)

#                     # Validate duration requirements based on frequency
#                     days_diff = (end_date.date() - start_date.date()).days
#                     if task_type == 'Daily':
#                         min_days = 2
#                         if days_diff < min_days:
#                             return JsonResponse({
#                                 'error': f'Daily tasks require at least {min_days} days difference between start and end dates (found: {days_diff} days)'
#                             }, status=400)
#                     elif task_type == 'Weekly':
#                         min_days = 7
#                         if days_diff < min_days:
#                             return JsonResponse({
#                                 'error': f'Weekly tasks require at least {min_days} days difference between start and end dates (found: {days_diff} days)'
#                             }, status=400)

#                     # Validate marking_criteria
#                     marking_criteria = task['marking_criteria']
#                     if not isinstance(marking_criteria, dict) or not all(key in marking_criteria for key in ['fully_completed', 'partially_completed', 'incomplete']):
#                         return JsonResponse({'error': f'Invalid task marking_criteria in task {task_index + 1} of level {level_index + 1}'}, status=400)
#                     for key, value in marking_criteria.items():
#                         if not isinstance(value, (int, float)) or value < 0:
#                             return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} marking_criteria {key} must be a non-negative number'}, status=400)
#                     if not (marking_criteria['fully_completed'] <= task['points'] and
#                             marking_criteria['fully_completed'] > marking_criteria['partially_completed'] > marking_criteria['incomplete']):
#                         return JsonResponse({'error': 'Marking criteria must follow: fully_completed <= task points, fully_completed > partially_completed > incomplete'}, status=400)

#                     # Validate subtasks
#                     subtasks = task.get('subtasks', [])
#                     if subtasks:
#                         if not isinstance(subtasks, list):
#                             return JsonResponse({'error': 'Subtasks must be a list'}, status=400)
#                         task_total_points = 0
#                         subtask_names = set()
#                         # Define date_regex for YYYY-MM-DD format
#                         date_regex = r'^\d{4}-\d{2}-\d{2}$'
#                         for subtask_index, subtask in enumerate(subtasks):
#                             subtask_required_fields = ['name', 'description', 'points', 'deadline']
#                             if not isinstance(subtask, dict) or not all(key in subtask for key in subtask_required_fields):
#                                 return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} must have name, description, points, and deadline'}, status=400)
#                             subtask_name = subtask['name'].strip()
#                             subtask_description = subtask['description'].strip()
#                             if not subtask_name:
#                                 return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} name cannot be empty or only whitespace'}, status=400)
#                             if not subtask_description:
#                                 return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} description cannot be empty or only whitespace'}, status=400)
#                             if subtask_name in subtask_names:
#                                 return JsonResponse({'error': f'Subtask names must be unique within task {task_index + 1} of level {level_index + 1}'}, status=400)
#                             subtask_names.add(subtask_name)
#                             if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', subtask_name):
#                                 return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} name contains invalid characters'}, status=400)
#                             if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', subtask_description):
#                                 return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} description contains invalid characters'}, status=400)
#                             if len(subtask_name) > 100:
#                                 return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} name exceeds 100 characters'}, status=400)
#                             if len(subtask_description) > 500:
#                                 return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} description exceeds 500 characters'}, status=400)
#                             if not isinstance(subtask['points'], (int, float)) or subtask['points'] < 0:
#                                 return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} points must be a non-negative number'}, status=400)
#                             if subtask['points'] > 10000:
#                                 return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} points cannot exceed 10000'}, status=400)

#                             if not re.match(date_regex, subtask['deadline']):
#                                 return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} deadline must be in YYYY-MM-DD format'}, status=400)
#                             try:
#                                 subtask_deadline = datetime.strptime(subtask['deadline'], '%Y-%m-%d')
#                                 if subtask_deadline.date() >= end_date.date():
#                                     return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} deadline must be before task end_date'}, status=400)
#                                 if subtask_deadline.date() <= start_date.date():
#                                     return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} deadline must be after task start_date'}, status=400)
#                             except ValueError:
#                                 return JsonResponse({'error': 'Invalid subtask deadline format. Use YYYY-MM-DD'}, status=400)
                            
#                             # Check for subtask deadline_time
#                             subtask_deadline_time = subtask.get('deadline_time')
#                             if subtask_deadline_time:
#                                 try:
#                                     datetime.strptime(subtask_deadline_time, '%H:%M')
#                                 except ValueError:
#                                     return JsonResponse({'error': 'Invalid subtask deadline_time format. Use HH:MM (24-hour format)'}, status=400)
                                
#                                 # Add full deadline to subtask
#                                 subtask['full_deadline'] = f"{subtask['deadline']}T{subtask_deadline_time}:00"
#                             else:
#                                 # Default to end of day
#                                 subtask['deadline_time'] = '23:59'
#                                 subtask['full_deadline'] = f"{subtask['deadline']}T23:59:00"
                            
#                             task_total_points += subtask['points']

#                         if task_total_points == 0:
#                             return JsonResponse({'error': f'At least one subtask in task {task_index + 1} of level {level_index + 1} must have positive points'}, status=400)
#                         if task_total_points != task['points']:
#                             print(f"Task points mismatch in task {task_index + 1} of level {level_index + 1}: task.points={task['points']}, sum of subtask points={task_total_points}")
#                             return JsonResponse({'error': f'Sum of subtask points must equal task points in task {task_index + 1} of level {level_index + 1}'}, status=400)
#                         task['total_points'] = task_total_points
#                     else:
#                         task['total_points'] = task['points']

#                     # Add deadline and frequency data to task
#                     task['deadline_time'] = deadline_time
#                     task['full_deadline'] = full_deadline
#                     task['frequency'] = task_type
#                     task['last_updated'] = None
#                     task['update_history'] = []
#                     task['deadline'] = task['end_date']

#                 # Calculate total points for the level
#                 level_total_points = sum(task['total_points'] for task in tasks)
#                 level['total_points'] = level_total_points

#             # Create task document
#             task_document = {
#                 '_id': ObjectId(),
#                 'event_name': event_name,
#                 'assigned_to': [
#                     {'name': admin['name'], 'admin_id': admin['admin_id']} 
#                     for admin in assigned_admins
#                 ],
#                 'levels': [
#                     {
#                         'level_id': str(uuid.uuid4()),
#                         'level_name': level['level_name'].strip(),
#                         'total_points': level['total_points'],
#                         'tasks': [
#                             {
#                                 'task_id': str(uuid.uuid4()),
#                                 'task_name': task['task_name'].strip(),
#                                 'description': task['description'].strip(),
#                                 'total_points': task['total_points'],
#                                 'subtasks': [
#                                     {
#                                         'subtask_id': str(uuid.uuid4()),
#                                         'name': subtask['name'].strip(),
#                                         'description': subtask['description'].strip(),
#                                         'points': subtask['points'],
#                                         'deadline': subtask['deadline'],
#                                         'deadline_time': subtask.get('deadline_time', '23:59'),
#                                         'full_deadline': subtask.get('full_deadline', f"{subtask['deadline']}T23:59:00"),
#                                         'status': 'incomplete',
#                                         'completion_history': []
#                                     } for subtask in task.get('subtasks', [])
#                                 ],
#                                 'deadline': task['deadline'],
#                                 'deadline_time': task.get('deadline_time', '23:59'),
#                                 'full_deadline': task.get('full_deadline', f"{task['end_date']}T23:59:00"),
#                                 'frequency': task['frequency'],
#                                 'start_date': task['start_date'],
#                                 'end_date': task['end_date'],
#                                 'marking_criteria': task['marking_criteria'],
#                                 'last_updated': None,
#                                 'update_history': [],
#                                 'next_update_due': start_date.date().isoformat() if task['frequency'] != 'Once' else None,
#                                 'task_status': 'pending'
#                             } for task in level['tasks']
#                         ]
#                     } for level in levels
#                 ],
#                 'created_at': datetime.now(),
#                 'updated_at': datetime.now(),
#                 'has_recurring_tasks': any(
#                     any(task.get('frequency', 'Once') != 'Once' for task in level['tasks'])
#                     for level in levels
#                 )
#             }

#             # Insert task document
#             tasks_collection.insert_one(task_document)
            
#             # Get the ObjectId of the newly created task document
#             event_id = str(task_document['_id'])

#             # Create mapped events document
#             mapped_event_document = {
#                 '_id': ObjectId(),
#                 'event_name': event_name,
#                 'event_id': event_id,
#                 'assigned_admins': [
#                     {
#                         'admin_id': admin['admin_id'],
#                         'name': admin['name'],
#                         'users': [{'email': student['email']} for student in admin['students']]
#                     } for admin in assigned_admins
#                 ],
#                 'created_at': datetime.now()
#             }
#             try:
#                 mapped_events_collection.insert_one(mapped_event_document)
#             except DuplicateKeyError:
#                 return JsonResponse({'error': 'Failed to insert mapped event due to duplicate key'}, status=500)
#             except Exception as e:
#                 print(f"Error inserting mapped event document: {str(e)}")
#                 return JsonResponse({'error': 'Failed to insert mapped event document'}, status=500)

#             # Prepare response
#             response = {
#                 'object_id': event_id,
#                 'message': 'Event created successfully',
#                 'event_name': event_name,
#                 'assigned_to': [admin['name'] for admin in assigned_admins],
#                 'has_recurring_tasks': task_document.get('has_recurring_tasks', False)
#             }

#             return JsonResponse(response, status=201)

#         except Exception as e:
#             return JsonResponse({'error': str(e)}, status=500)
#     else:
#         return JsonResponse({'error': 'Method not allowed'}, status=405)  

@csrf_exempt
def create_task(request):
    if request.method == 'POST':
        try:
            # MongoDB connection setup
            tasks_collection = db['events']
            admins_collection = db['admin']
            students_collection = db['users']
            mapped_events_collection = db['Mapped_Events']

            # Parse request data
            try:
                data = json.loads(request.body) if request.content_type == 'application/json' else request.POST.dict()
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON format'}, status=400)

            # Validate required fields
            required_fields = ['event_name', 'levels', 'assigned_to']
            if not all(field in data for field in required_fields):
                return JsonResponse({'error': 'Missing required fields: event_name, levels, assigned_to'}, status=400)
            
            # Validate event_name
            event_name = data['event_name']
            if not isinstance(event_name, str) or not event_name.strip():
                return JsonResponse({'error': 'Event name must be a non-empty string'}, status=400)
            if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', event_name):
                return JsonResponse({'error': 'Event name contains invalid characters'}, status=400)
            if len(event_name.strip()) > 100:
                return JsonResponse({'error': 'Event name exceeds 100 characters'}, status=400)
            event_name = event_name.strip()

            # Validate assigned_to
            assigned_to = data['assigned_to']
            if not isinstance(assigned_to, list) or not assigned_to:
                return JsonResponse({'error': 'Assigned_to must be a non-empty list of admin names or IDs'}, status=400)

            # Validate admins and collect admin details
            admin_ids = []
            assigned_admins = []
            for admin_identifier in assigned_to:
                # Try finding admin by Admin_ID first, then by name
                admin = admins_collection.find_one({'Admin_ID': admin_identifier, 'status': 'Active'})
                if not admin:
                    admin = admins_collection.find_one({'name': admin_identifier, 'status': 'Active'})
                if not admin:
                    return JsonResponse({'error': f'Invalid or inactive admin: {admin_identifier}'}, status=400)
                admin_id = admin['Admin_ID']
                admin_name = admin['name']
                admin_ids.append(admin_id)

                # Fetch students for this admin
                students = students_collection.find(
                    {'admin_id': admin_id},
                    {'_id': 0, 'name': 1, 'roll_no': 1, 'email': 1}
                )
                seen_roll_nos = set()
                admin_students = []
                for student in students:
                    if not all(key in student for key in ['name', 'roll_no']):
                        continue  # Skip invalid student records
                    if student['roll_no'] not in seen_roll_nos:
                        admin_students.append({
                            'name': student['name'],
                            'roll_no': student['roll_no'],
                            'email': student.get('email', '')
                        })
                        seen_roll_nos.add(student['roll_no'])       
                
                assigned_admins.append({
                    'admin_id': admin_id,
                    'name': admin_name,
                    'students': admin_students
                })
                
                if not admin_students:
                    print(f"No students found for admin_id: {admin_id}")

            # Validate levels structure
            levels = data['levels']
            if not isinstance(levels, list) or not levels:
                return JsonResponse({'error': 'Levels must be a non-empty list'}, status=400)
            if len(levels) > 50:
                return JsonResponse({'error': 'Too many levels (max 50)'}, status=400)

            # Check for duplicate level names
            level_names = [level['level_name'].strip() for level in levels]
            if len(set(level_names)) != len(level_names):
                return JsonResponse({'error': 'Level names must be unique within the event'}, status=400)

            # Process each level
            for level_index, level in enumerate(levels):
                if not isinstance(level, dict) or not all(key in level for key in ['level_name', 'tasks']):
                    return JsonResponse({'error': f'Level {level_index + 1} must have level_name and tasks'}, status=400)
                level_name = level['level_name'].strip()
                if not level_name:
                    return JsonResponse({'error': f'Level {level_index + 1} name cannot be empty or only whitespace'}, status=400)
                if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', level_name):
                    return JsonResponse({'error': f'Level {level_index + 1} name contains invalid characters'}, status=400)
                if len(level_name) > 100:
                    return JsonResponse({'error': f'Level {level_index + 1} name exceeds 100 characters'}, status=400)

                tasks = level['tasks']
                if not isinstance(tasks, list) or not tasks:
                    return JsonResponse({'error': f'Tasks must be a non-empty list for level {level_index + 1}'}, status=400)
                if len(tasks) > 100:
                    return JsonResponse({'error': f'Too many tasks in level {level_index + 1} (max 100)'}, status=400)

                # Check for duplicate task names within the level
                task_names = [task['task_name'].strip() for task in tasks]
                if len(set(task_names)) != len(task_names):
                    return JsonResponse({'error': f'Task names must be unique within level {level_index + 1}'}, status=400)

                # Process each task within the level
                for task_index, task in enumerate(tasks):
                    # Required fields for all tasks
                    base_required_fields = ['task_name', 'description', 'points', 'start_date', 'end_date']
                    for field in base_required_fields:
                        if field not in task:
                            return JsonResponse({'error': f'Missing required task field {field} in task {task_index + 1} of level {level_index + 1}'}, status=400)

                    task_name = task['task_name'].strip()
                    description = task['description'].strip()
                    if not task_name:
                        return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} name cannot be empty or only whitespace'}, status=400)
                    if not description:
                        return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} description cannot be empty or only whitespace'}, status=400)
                    if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', task_name):
                        return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} name contains invalid characters'}, status=400)
                    if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', description):
                        return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} description contains invalid characters'}, status=400)
                    if len(task_name) > 100:
                        return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} name exceeds 100 characters'}, status=400)
                    if len(description) > 500:
                        return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} description exceeds 500 characters'}, status=400)
                    if not isinstance(task['points'], (int, float)) or task['points'] <= 0:
                        return JsonResponse({'error': 'Task points must be a positive number'}, status=400)

                    # Validate dates
                    try:
                        start_date = datetime.strptime(task['start_date'], '%Y-%m-%d')
                        if start_date.date() < datetime.now().date():
                            return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} start_date cannot be in the past'}, status=400)
                        end_date = datetime.strptime(task['end_date'], '%Y-%m-%d')
                        if end_date.date() <= start_date.date():
                            return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} end_date must be after start_date'}, status=400)
                    except ValueError:
                        return JsonResponse({'error': f'Invalid date format in task {task_index + 1} of level {level_index + 1}. Use YYYY-MM-DD'}, status=400)

                    # Validate deadline_time (optional)
                    deadline_time = task.get('deadline_time')
                    if deadline_time:
                        try:
                            datetime.strptime(deadline_time, '%H:%M')
                        except ValueError:
                            return JsonResponse({'error': 'Invalid deadline_time format. Use HH:MM (24-hour format)'}, status=400)
                    else:
                        deadline_time = '23:59'

                    # Create full deadline datetime by combining date and time
                    full_deadline = f"{task['end_date']}T{deadline_time}:00"

                    # Validate task_type (optional field)
                    task_type = task.get('task_type', 'Once')
                    if task_type not in ['Once', 'Daily', 'Weekly']:
                        return JsonResponse({'error': 'Task type must be "Once", "Daily", or "Weekly"'}, status=400)

                    # Validate duration requirements based on frequency
                    days_diff = (end_date.date() - start_date.date()).days
                    if task_type == 'Daily':
                        min_days = 2
                        if days_diff < min_days:
                            return JsonResponse({
                                'error': f'Daily tasks require at least {min_days} days difference between start and end dates (found: {days_diff} days)'
                            }, status=400)
                    elif task_type == 'Weekly':
                        min_days = 7
                        if days_diff < min_days:
                            return JsonResponse({
                                'error': f'Weekly tasks require at least {min_days} days difference between start and end dates (found: {days_diff} days)'
                            }, status=400)

                    # Validate subtasks
                    subtasks = task.get('subtasks', [])
                    has_subtasks = bool(subtasks)
                    if has_subtasks:
                        if not isinstance(subtasks, list):
                            return JsonResponse({'error': 'Subtasks must be a list'}, status=400)
                        task_total_points = 0
                        subtask_names = set()
                        date_regex = r'^\d{4}-\d{2}-\d{2}$'
                        for subtask_index, subtask in enumerate(subtasks):
                            subtask_required_fields = ['name', 'description', 'points', 'start_date', 'end_date', 'marking_criteria']
                            if not isinstance(subtask, dict) or not all(key in subtask for key in subtask_required_fields):
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} must have name, description, points, start_date, end_date, marking_criteria'}, status=400)
                            subtask_name = subtask['name'].strip()
                            subtask_description = subtask['description'].strip()
                            if not subtask_name:
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} name cannot be empty or only whitespace'}, status=400)
                            if not subtask_description:
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} description cannot be empty or only whitespace'}, status=400)
                            if subtask_name in subtask_names:
                                return JsonResponse({'error': f'Subtask names must be unique within task {task_index + 1} of level {level_index + 1}'}, status=400)
                            subtask_names.add(subtask_name)
                            if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', subtask_name):
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} name contains invalid characters'}, status=400)
                            if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', subtask_description):
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} description contains invalid characters'}, status=400)
                            if len(subtask_name) > 100:
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} name exceeds 100 characters'}, status=400)
                            if len(subtask_description) > 500:
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} description exceeds 500 characters'}, status=400)
                            if not isinstance(subtask['points'], (int, float)) or subtask['points'] < 0:
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} points must be a non-negative number'}, status=400)
                            if subtask['points'] > 10000:
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} points cannot exceed 10000'}, status=400)

                            # Validate subtask start_date and end_date
                            if not re.match(date_regex, subtask['start_date']):
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} start_date must be in YYYY-MM-DD format'}, status=400)
                            if not re.match(date_regex, subtask['end_date']):
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} end_date must be in YYYY-MM-DD format'}, status=400)
                            try:
                                subtask_start_date = datetime.strptime(subtask['start_date'], '%Y-%m-%d')
                                subtask_end_date = datetime.strptime(subtask['end_date'], '%Y-%m-%d')
                                if subtask_start_date.date() < start_date.date():
                                    return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} start_date must be on or after task start_date'}, status=400)
                                if subtask_end_date.date() > end_date.date():
                                    return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} end_date must be on or before task end_date'}, status=400)
                                if subtask_end_date.date() <= subtask_start_date.date():
                                    return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} end_date must be after start_date'}, status=400)
                            except ValueError:
                                return JsonResponse({'error': f'Invalid date format in subtask {subtask_index + 1} of task {task_index + 1} of level {level_index + 1}. Use YYYY-MM-DD'}, status=400)

                            # Set deadline to end_date for backward compatibility
                            subtask['deadline'] = subtask['end_date']

                            # Validate subtask task_type (optional field)
                            subtask_task_type = subtask.get('task_type', 'Once')
                            if subtask_task_type not in ['Once', 'Daily', 'Weekly']:
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} task type must be "Once", "Daily", or "Weekly"'}, status=400)

                            # Validate duration requirements based on frequency for subtasks
                            subtask_days_diff = (subtask_end_date.date() - subtask_start_date.date()).days
                            if subtask_task_type == 'Daily':
                                min_days = 2
                                if subtask_days_diff < min_days:
                                    return JsonResponse({
                                        'error': f'Daily subtasks require at least {min_days} days difference between start and end dates (found: {subtask_days_diff} days)'
                                    }, status=400)
                            elif subtask_task_type == 'Weekly':
                                min_days = 7
                                if subtask_days_diff < min_days:
                                    return JsonResponse({
                                        'error': f'Weekly subtasks require at least {min_days} days difference between start and end dates (found: {subtask_days_diff} days)'
                                    }, status=400)

                            # Check for subtask deadline_time
                            subtask_deadline_time = subtask.get('deadline_time')
                            if subtask_deadline_time:
                                try:
                                    datetime.strptime(subtask_deadline_time, '%H:%M')
                                except ValueError:
                                    return JsonResponse({'error': 'Invalid subtask deadline_time format. Use HH:MM (24-hour format)'}, status=400)
                                subtask['full_deadline'] = f"{subtask['end_date']}T{subtask_deadline_time}:00"
                            else:
                                subtask['deadline_time'] = '23:59'
                                subtask['full_deadline'] = f"{subtask['end_date']}T23:59:00"

                            # Set frequency for subtask
                            subtask['frequency'] = subtask_task_type

                            # Validate marking_criteria for subtask
                            marking_criteria = subtask['marking_criteria']
                            if not isinstance(marking_criteria, dict) or not all(key in marking_criteria for key in ['fully_completed', 'partially_completed', 'incomplete']):
                                return JsonResponse({'error': f'Invalid subtask marking_criteria in subtask {subtask_index + 1} of task {task_index + 1} of level {level_index + 1}'}, status=400)
                            for key, value in marking_criteria.items():
                                if not isinstance(value, (int, float)) or value < 0:
                                    return JsonResponse({'error': f'Subtask {subtask_index + 1} in task {task_index + 1} of level {level_index + 1} marking_criteria {key} must be a non-negative number'}, status=400)
                            if not (marking_criteria['fully_completed'] <= subtask['points'] and
                                    marking_criteria['fully_completed'] > marking_criteria['partially_completed'] > marking_criteria['incomplete']):
                                return JsonResponse({'error': f'Subtask {subtask_index + 1} marking criteria must follow: fully_completed <= subtask points, fully_completed > partially_completed > incomplete'}, status=400)

                            task_total_points += subtask['points']

                        if task_total_points == 0:
                            return JsonResponse({'error': f'At least one subtask in task {task_index + 1} of level {level_index + 1} must have positive points'}, status=400)
                        if task_total_points != task['points']:
                            print(f"Task points mismatch in task {task_index + 1} of level {level_index + 1}: task.points={task['points']}, sum of subtask points={task_total_points}")
                            return JsonResponse({'error': f'Sum of subtask points must equal task points in task {task_index + 1} of level {level_index + 1}'}, status=400)
                        task['total_points'] = task_total_points
                        # Remove marking_criteria from parent task if subtasks exist
                        if 'marking_criteria' in task:
                            del task['marking_criteria']
                    else:
                        # No subtasks, so marking_criteria is required at task level
                        if 'marking_criteria' not in task:
                            return JsonResponse({'error': f'Missing marking_criteria in task {task_index + 1} of level {level_index + 1} (no subtasks)'}, status=400)
                        marking_criteria = task['marking_criteria']
                        if not isinstance(marking_criteria, dict) or not all(key in marking_criteria for key in ['fully_completed', 'partially_completed', 'incomplete']):
                            return JsonResponse({'error': f'Invalid task marking_criteria in task {task_index + 1} of level {level_index + 1}'}, status=400)
                        for key, value in marking_criteria.items():
                            if not isinstance(value, (int, float)) or value < 0:
                                return JsonResponse({'error': f'Task {task_index + 1} in level {level_index + 1} marking_criteria {key} must be a non-negative number'}, status=400)
                        if not (marking_criteria['fully_completed'] <= task['points'] and
                                marking_criteria['fully_completed'] > marking_criteria['partially_completed'] > marking_criteria['incomplete']):
                            return JsonResponse({'error': 'Marking criteria must follow: fully_completed <= task points, fully_completed > partially_completed > incomplete'}, status=400)
                        task['total_points'] = task['points']

                    # Add deadline and frequency data to task
                    task['deadline_time'] = deadline_time
                    task['full_deadline'] = full_deadline
                    task['frequency'] = task_type
                    task['last_updated'] = None
                    task['update_history'] = []
                    task['deadline'] = task['end_date']

                # Calculate total points for the level
                level_total_points = sum(task['total_points'] for task in tasks)
                level['total_points'] = level_total_points

            # Create task document
            task_document = {
                '_id': ObjectId(),
                'event_name': event_name,
                'assigned_to': [
                    {'name': admin['name'], 'admin_id': admin['admin_id']} 
                    for admin in assigned_admins
                ],
                'levels': [
                    {
                        'level_id': str(uuid.uuid4()),
                        'level_name': level['level_name'].strip(),
                        'total_points': level['total_points'],
                        'tasks': [
                            dict(
                                [
                                    ('task_id', str(uuid.uuid4())),
                                    ('task_name', task['task_name'].strip()),
                                    ('description', task['description'].strip()),
                                    ('total_points', task['total_points']),
                                    ('subtasks', [
                                        {
                                            'subtask_id': str(uuid.uuid4()),
                                            'name': subtask['name'].strip(),
                                            'description': subtask['description'].strip(),
                                            'points': subtask['points'],
                                            'deadline': subtask['deadline'],
                                            'deadline_time': subtask.get('deadline_time', '23:59'),
                                            'full_deadline': subtask.get('full_deadline', f"{subtask['deadline']}T23:59:00"),
                                            'frequency': subtask.get('frequency', 'Once'),
                                            'start_date': subtask['start_date'],
                                            'end_date': subtask['end_date'],
                                            'status': 'incomplete',
                                            'completion_history': [],
                                            # Add marking_criteria for subtask if present
                                            **({'marking_criteria': subtask['marking_criteria']} if 'marking_criteria' in subtask else {})
                                        } for subtask in task.get('subtasks', [])
                                    ]),
                                    ('deadline', task['deadline']),
                                    ('deadline_time', task.get('deadline_time', '23:59')),
                                    ('full_deadline', task.get('full_deadline', f"{task['end_date']}T23:59:00")),
                                    ('frequency', task['frequency']),
                                    ('start_date', task['start_date']),
                                    ('end_date', task['end_date']),
                                    # Only include marking_criteria if present (i.e., no subtasks)
                                    *([
                                        ('marking_criteria', task['marking_criteria'])
                                    ] if 'marking_criteria' in task else []),
                                    ('last_updated', None),
                                    ('update_history', []),
                                    ('next_update_due', start_date.date().isoformat() if task['frequency'] != 'Once' else None),
                                    ('task_status', 'pending')
                                ]
                            ) for task in level['tasks']
                        ]
                    } for level in levels
                ],
                'created_at': datetime.now(),
                'updated_at': datetime.now(),
                'has_recurring_tasks': any(
                    any(task.get('frequency', 'Once') != 'Once' for task in level['tasks'])
                    for level in levels
                )
            }

            # Insert task document
            tasks_collection.insert_one(task_document)
            
            # Get the ObjectId of the newly created task document
            event_id = str(task_document['_id'])

            # Create mapped events document
            mapped_event_document = {
                '_id': ObjectId(),
                'event_name': event_name,
                'event_id': event_id,
                'assigned_admins': [
                    {
                        'admin_id': admin['admin_id'],
                        'name': admin['name'],
                        'users': [{'email': student['email']} for student in admin['students']]
                    } for admin in assigned_admins
                ],
                'created_at': datetime.now()
            }
            try:
                mapped_events_collection.insert_one(mapped_event_document)
            except DuplicateKeyError:
                return JsonResponse({'error': 'Failed to insert mapped event due to duplicate key'}, status=500)
            except Exception as e:
                print(f"Error inserting mapped event document: {str(e)}")
                return JsonResponse({'error': 'Failed to insert mapped event document'}, status=500)

            # Prepare response
            response = {
                'object_id': event_id,
                'message': 'Event created successfully',
                'event_name': event_name,
                'assigned_to': [admin['name'] for admin in assigned_admins],
                'has_recurring_tasks': task_document.get('has_recurring_tasks', False)
            }

            return JsonResponse(response, status=201)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)  


@csrf_exempt
def update_task(request, event_id):
    if request.method == 'PUT':
        try:
            mongo_url = os.getenv('MONGO_URI')
            db_name = os.getenv('MONGO_DB_NAME', 'Leaderboard')
            client = MongoClient(mongo_url)
            db = client[db_name]
            tasks_collection = db['events']
            admins_collection = db['admin']
            students_collection = db['users']
            mapped_events_collection = db['Mapped_Events']

            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON format'}, status=400)

            required_fields = ['event_name', 'levels', 'assigned_to']
            if not all(field in data for field in required_fields):
                return JsonResponse({'error': 'Missing required fields: event_name, levels, assigned_to'}, status=400)

            event_name = data['event_name']
            if not isinstance(event_name, str) or not event_name.strip():
                return JsonResponse({'error': 'Event name must be a non-empty string'}, status=400)
            if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', event_name):
                return JsonResponse({'error': 'Event name contains invalid characters'}, status=400)

            assigned_to = data['assigned_to']
            if not isinstance(assigned_to, list) or not assigned_to:
                return JsonResponse({'error': 'Assigned_to must be a non-empty list of admin names'}, status=400)

            admin_ids = []
            assigned_admins = []
            for admin_name in assigned_to:
                admin = admins_collection.find_one({'name': admin_name, 'status': 'Active'})
                if not admin:
                    return JsonResponse({'error': f'Invalid or inactive admin: {admin_name}'}, status=400)
                admin_id = admin['Admin_ID']
                admin_ids.append(admin_id)

                students = students_collection.find(
                    {'admin_id': admin_id},
                    {'_id': 0, 'name': 1, 'roll_no': 1, 'email': 1}
                )
                seen_roll_nos = set()
                admin_students = []
                for student in students:
                    if student['roll_no'] not in seen_roll_nos:
                        admin_students.append({
                            'name': student['name'],
                            'roll_no': student['roll_no'],
                            'email': student.get('email', '')
                        })
                        seen_roll_nos.add(student['roll_no'])
                
                assigned_admins.append({
                    'admin_id': admin_id,
                    'name': admin_name,
                    'students': admin_students
                })

            levels = data['levels']
            if not isinstance(levels, list) or not levels:
                return JsonResponse({'error': 'Levels must be a non-empty list'}, status=400)

            for level in levels:
                if not isinstance(level, dict) or not all(key in level for key in ['level_name', 'tasks']):
                    return JsonResponse({'error': 'Each level must have level_name and tasks'}, status=400)
                if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', level['level_name']):
                    return JsonResponse({'error': 'Level name contains invalid characters'}, status=400)

                tasks = level['tasks']
                if not isinstance(tasks, list) or not tasks:
                    return JsonResponse({'error': 'Tasks must be a non-empty list for each level'}, status=400)

                for task in tasks:
                    task_required_fields = ['task_name', 'description', 'points', 'start_date', 'end_date', 'marking_criteria']
                    if not all(field in task for field in task_required_fields):
                        return JsonResponse({'error': 'Missing required task fields: task_name, description, points, start_date, end_date, marking_criteria'}, status=400)

                    if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', task['task_name']):
                        return JsonResponse({'error': 'Task name contains invalid characters'}, status=400)
                    if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', task['description']):
                        return JsonResponse({'error': 'Task description contains invalid characters'}, status=400)
                    if not isinstance(task['points'], (int, float)) or task['points'] <= 0:
                        return JsonResponse({'error': 'Task points must be a positive number'}, status=400)

                    try:
                        start_date = datetime.strptime(task['start_date'], '%Y-%m-%d')
                        if start_date.date() < datetime.now().date():
                            return JsonResponse({'error': 'Task start_date cannot be in the past'}, status=400)
                        end_date = datetime.strptime(task['end_date'], '%Y-%m-%d')
                        if end_date.date() <= start_date.date():
                            return JsonResponse({'error': 'Task end_date must be after start_date'}, status=400)
                    except ValueError:
                        return JsonResponse({'error': 'Invalid start_date or end_date format. Use YYYY-MM-DD'}, status=400)

                    deadline_time = task.get('deadline_time')
                    if deadline_time:
                        try:
                            datetime.strptime(deadline_time, '%H:%M')
                        except ValueError:
                            return JsonResponse({'error': 'Invalid deadline_time format. Use HH:MM (24-hour format)'}, status=400)
                    else:
                        deadline_time = '23:59'

                    full_deadline = f"{task['end_date']}T{deadline_time}:00"
                    
                    task_type = task.get('task_type', 'Once')
                    if task_type not in ['Once', 'Daily', 'Weekly']:
                        return JsonResponse({'error': 'Task type must be "Once", "Daily", or "Weekly"'}, status=400)

                    days_diff = (end_date.date() - start_date.date()).days
                    if task_type == 'Daily':
                        min_days = 2
                        if days_diff < min_days:
                            return JsonResponse({
                                'error': f'Daily tasks require at least {min_days} days difference between start and end dates (found: {days_diff} days)'
                            }, status=400)
                    elif task_type == 'Weekly':
                        min_days = 7
                        if days_diff < min_days:
                            return JsonResponse({
                                'error': f'Weekly tasks require at least {min_days} days difference between start and end dates (found: {days_diff} days)'
                            }, status=400)

                    marking_criteria = task['marking_criteria']
                    if not all(key in marking_criteria for key in ['fully_completed', 'partially_completed', 'incomplete']):
                        return JsonResponse({'error': 'Invalid task marking criteria'}, status=400)
                    for key, value in marking_criteria.items():
                        if not isinstance(value, (int, float)) or value < 0:
                            return JsonResponse({'error': f'Task marking criteria {key} must be a non-negative number'}, status=400)
                    if not (marking_criteria['fully_completed'] <= task['points'] and
                            marking_criteria['fully_completed'] > marking_criteria['partially_completed'] > marking_criteria['incomplete']):
                        return JsonResponse({'error': 'Marking criteria must follow: fully_completed <= task points, fully_completed > partially_completed > incomplete'}, status=400)

                    subtasks = task.get('subtasks', [])
                    if subtasks:
                        if not isinstance(subtasks, list):
                            return JsonResponse({'error': 'Subtasks must be a list'}, status=400)
                        task_total_points = 0
                        for subtask in subtasks:
                            subtask_required_fields = ['name', 'description', 'points', 'deadline']
                            if not isinstance(subtask, dict) or not all(key in subtask for key in subtask_required_fields):
                                return JsonResponse({'error': 'Each subtask must have name, description, points, and deadline'}, status=400)
                            if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', subtask['name']):
                                return JsonResponse({'error': 'Subtask name contains invalid characters'}, status=400)
                            if not re.match(r'^[a-zA-Z0-9\s\-.,!&()]+$', subtask['description']):
                                return JsonResponse({'error': 'Subtask description contains invalid characters'}, status=400)
                            if not isinstance(subtask['points'], (int, float)) or subtask['points'] <= 0:
                                return JsonResponse({'error': 'Subtask points must be a positive number'}, status=400)

                            try:
                                subtask_deadline = datetime.strptime(subtask['deadline'], '%Y-%m-%d')
                                if subtask_deadline.date() > end_date.date():
                                    return JsonResponse({'error': 'Subtask deadline cannot exceed task end_date'}, status=400)
                                if subtask_deadline.date() < start_date.date():
                                    return JsonResponse({'error': 'Subtask deadline cannot be before task start_date'}, status=400)
                            except ValueError:
                                return JsonResponse({'error': 'Invalid subtask deadline format. Use YYYY-MM-DD'}, status=400)
                            
                            subtask_deadline_time = subtask.get('deadline_time')
                            if subtask_deadline_time:
                                try:
                                    datetime.strptime(subtask_deadline_time, '%H:%M')
                                except ValueError:
                                    return JsonResponse({'error': 'Invalid subtask deadline_time format. Use HH:MM (24-hour format)'}, status=400)
                                
                                subtask['full_deadline'] = f"{subtask['deadline']}T{subtask_deadline_time}:00"
                            else:
                                subtask['deadline_time'] = '23:59'
                                subtask['full_deadline'] = f"{subtask['deadline']}T23:59:00"
                            
                            task_total_points += subtask['points']
                        
                        if task_total_points != task['points']:
                            print(f"Task points mismatch: task.points={task['points']}, sum of subtask points={task_total_points}")
                            return JsonResponse({'error': 'Sum of subtask points must equal task points'}, status=400)
                        task['total_points'] = task_total_points
                    else:
                        task['total_points'] = task['points']

                    task['deadline_time'] = deadline_time
                    task['full_deadline'] = full_deadline
                    task['frequency'] = task_type
                    task['deadline'] = task['end_date']

                level_total_points = sum(task['total_points'] for task in tasks)
                level['total_points'] = level_total_points

            task_document = {
                'event_name': event_name,
                'assigned_to': [
                    {'name': admin_name, 'admin_id': admin['Admin_ID']} 
                    for admin_name, admin in [(a, admins_collection.find_one({'name': a, 'status': 'Active'})) for a in assigned_to]
                ],
                'levels': [
                    {
                        'level_id': level.get('level_id', str(uuid.uuid4())),
                        'level_name': level['level_name'],
                        'total_points': level['total_points'],
                        'tasks': [
                            {
                                'task_id': task.get('task_id', str(uuid.uuid4())),
                                'task_name': task['task_name'],
                                'description': task['description'],
                                'total_points': task['total_points'],
                                'subtasks': [
                                    {
                                        'subtask_id': subtask.get('subtask_id', str(uuid.uuid4())),
                                        'name': subtask['name'],
                                        'description': subtask['description'],
                                        'points': subtask['points'],
                                        'deadline': subtask['deadline'],
                                        'deadline_time': subtask.get('deadline_time', '23:59'),
                                        'full_deadline': subtask.get('full_deadline', f"{subtask['deadline']}T23:59:00"),
                                        'status': subtask.get('status', 'incomplete'),
                                        'completion_history': subtask.get('completion_history', [])
                                    } for subtask in task.get('subtasks', [])
                                ],
                                'deadline': task['deadline'],
                                'deadline_time': task.get('deadline_time', '23:59'),
                                'full_deadline': task.get('full_deadline', f"{task['end_date']}T23:59:00"),
                                'frequency': task['frequency'],
                                'start_date': task['start_date'],
                                'end_date': task['end_date'],
                                'marking_criteria': task['marking_criteria'],
                                'last_updated': None,
                                'update_history': [],
                                'next_update_due': start_date.date().isoformat() if task['frequency'] != 'Once' else None,
                                'task_status': task.get('task_status', 'pending')
                            } for task in level['tasks']
                        ]
                    } for level in levels
                ],
                'updated_at': datetime.now(),
                'has_recurring_tasks': any(
                    any(task.get('frequency', 'Once') != 'Once' for task in level['tasks'])
                    for level in levels
                )
            }

            result = tasks_collection.update_one(
                {'_id': ObjectId(event_id)},
                {'$set': task_document}
            )

            if result.matched_count == 0:
                return JsonResponse({'error': 'Event not found'}, status=404)

            mapped_events_collection.update_one(
                {'event_id': event_id},
                {
                    '$set': {
                        'event_name': event_name,
                        'assigned_admins': [
                            {
                                'admin_id': admin['admin_id'],
                                'name': admin['name'],
                                'users': [{'email': student['email']} for student in admin['students']]
                            } for admin in assigned_admins
                        ],
                        'updated_at': datetime.now()
                    }
                }
            )

            response = {
                'object_id': event_id,
                'message': 'Event updated successfully',
                'event_name': event_name,
                'assigned_to': [admin['name'] for admin in assigned_admins],
                'has_recurring_tasks': task_document.get('has_recurring_tasks', False)
            }

            return JsonResponse(response, status=200)

        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': f'Unexpected error: {str(e)}'}, status=500)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def delete_task(request, event_id):
    if request.method == 'DELETE':
        try:
            result = tasks_collection.delete_one({'_id': ObjectId(event_id)})
            if result.deleted_count == 0:
                return JsonResponse({'error': 'Event not found'}, status=404)

            mapped_events_collection.delete_one({'event_id': event_id})

            return JsonResponse({'message': 'Event deleted successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)   
 
@csrf_exempt
def fetch_all_tasks_for_superadmin(request):
    if request.method == 'GET':
        try:
            # Get MongoDB tasks collection
            collection_name = 'events'
            tasks_collection = db[collection_name]  # Use the actual collection object, not a string

            # Fetch all task documents with relevant fields
            tasks = list(tasks_collection.find({}, {
                '_id': 1,
                'event_name': 1,
                'assigned_to': 1,
                'levels': 1,
                'created_at': 1,
                'updated_at': 1,
                'has_recurring_tasks': 1  # Include has_recurring_tasks field
            }))

            # Convert ObjectId and datetime for JSON serialization
            for task in tasks:
                task['_id'] = str(task['_id'])
                
                # Handle datetime objects safely
                if isinstance(task.get('created_at'), datetime):
                    task['created_at'] = task['created_at'].isoformat()
                if isinstance(task.get('updated_at'), datetime):
                    task['updated_at'] = task['updated_at'].isoformat()
                
                # Process levels, tasks, and subtasks
                for level in task.get('levels', []):
                    if 'level_id' in level:
                        level['level_id'] = str(level['level_id'])
                    
                    for t in level.get('tasks', []):
                        if 'task_id' in t:
                            t['task_id'] = str(t['task_id'])
                        
                        # Make sure subtasks exists before trying to iterate
                        for subtask in t.get('subtasks', []):
                            if 'subtask_id' in subtask:
                                subtask['subtask_id'] = str(subtask['subtask_id'])

            # Return response
            return JsonResponse({'tasks': tasks}, status=200)

        except Exception as e:
            # Log the error for debugging
            import traceback
            print(f"Error in fetch_all_tasks_for_superadmin: {str(e)}")
            print(traceback.format_exc())
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
   
def send_invitation_email_logic(email: str, event_name: str, full_name: str = None, is_login: bool = True, token: str = None) -> tuple[bool, str]:
    greeting = f"Hi {full_name}," if full_name else "Dear Participant,"
    link = f"http://localhost:5173/studentlogin" if is_login else f"http://localhost:5173/studentsignup?token={token}&email={email}"
    try:
        send_mail(
            subject=f'Invitation to Participate in {event_name}',
            message=f"""
                {greeting}

                You have been invited to participate in the event "{event_name}" on the Students Leaderboard platform.

                {'Please log in to your account to view the event details and tasks.' if is_login else 'Please sign up to create an account and participate in the event.'}
                {link}

                Best regards,
                SuperAdmin Team
                """,
            from_email="studentleaderdashboard@gmail.com",
            recipient_list=[email],
            fail_silently=False,
        )
        return True, f"Invitation email sent successfully to {email}"
    except Exception as e:
        print(f"Email sending failed for {email}: {str(e)}")
        return False, f"Failed to send email to {email}: {str(e)}"

@csrf_exempt
def assign_users(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            print(f"Received payload: {data}")
            event_id = data.get('event_id')
            assignments = data.get('assignments', [])

            if not event_id:
                return JsonResponse({'error': 'Missing event_id'}, status=400)
            if not assignments:
                return JsonResponse({'error': 'Missing or empty assignments array'}, status=400)

            # Look up event by _id
            event = tasks_collection.find_one({'_id': ObjectId(event_id)})
            if not event:
                return JsonResponse({'error': 'Event not found'}, status=404)
            event_name = event.get('event_name', 'Event')
            
            # Get existing mapped event
            existing_event = mapped_events_collection.find_one({'event_id': event_id})
            existing_users_by_admin = {}
            all_assigned_users = set()  # Track all users assigned to any admin for this event

            if existing_event and 'assigned_admins' in existing_event:
                for admin in existing_event['assigned_admins']:
                    existing_users_by_admin[admin['admin_id']] = {
                        user['email'] for user in admin.get('users', [])
                    }
                    # Collect all assigned users for duplicate check
                    all_assigned_users.update(existing_users_by_admin[admin['admin_id']])

            email_failures = []
            updated_admins = []
            user_to_admin_map = {}  # Track user assignments in current request

            for assignment in assignments:
                admin_id = assignment.get('admin_id')
                emails = assignment.get('emails', [])

                if not admin_id:
                    return JsonResponse({'error': 'Missing admin_id in assignment'}, status=400)
                if not isinstance(emails, list):
                    return JsonResponse({'error': f'Emails must be a list for admin {admin_id}'}, status=400)

                admin = admin_collection.find_one({'Admin_ID': admin_id, 'status': 'Active'})
                if not admin:
                    return JsonResponse({'error': f'Invalid or inactive admin: {admin_id}'}, status=400)
                existing_emails = existing_users_by_admin.get(admin_id, set())
                admin_users = []
                for email in emails:
                    if not isinstance(email, str) or not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
                        email_failures.append({'email': email, 'reason': 'Invalid email format'})
                        continue

                    # Check for duplicate assignments in current request
                    if email in user_to_admin_map:
                        conflicting_admin = user_to_admin_map[email]
                        print(f"Conflict detected in request: {email} is assigned under both {conflicting_admin} and {admin_id}")
                        return JsonResponse({
                            'error': f"User {email} is assigned under multiple admins ({conflicting_admin}, {admin_id}) in the same event."
                        }, status=400)

                    # Check for duplicate assignments in existing database
                    if email in all_assigned_users and email not in existing_emails:
                        # Find the admin who already has this user
                        for existing_admin_id, users in existing_users_by_admin.items():
                            if email in users:
                                conflicting_admin = existing_admin_id
                                print(f"Conflict detected in DB: {email} is already assigned to {conflicting_admin}")
                                return JsonResponse({
                                    'error': f"User {email} is already assigned to admin {conflicting_admin} in this event."
                                }, status=400)

                    # Step 1: Upsert basic user document
                    student_data_collection.update_one(
                        {'email': email},
                        {'$setOnInsert': {'created_at': datetime.now(timezone.utc)}},
                        upsert=True
                    )

                    # Step 2: Fetch full user doc
                    student = student_data_collection.find_one({'email': email})
                    has_account = bool(student) and all(
                        student.get(field) for field in ['name', 'student_id', 'department', 'password']
                    )
                    full_name = student.get('name') if student else None
                    token = None

                    # Step 3: If not a full account, update with token info
                    if not has_account:
                        token = generate_setup_token(str(student['_id']))
                        student_data_collection.update_one(
                            {'_id': student['_id']},
                            {
                                '$set': {
                                    'password_set': False,
                                    'status': "Pending",
                                    'password_setup_token': token,
                                    'password_setup_token_expiry': datetime.now() + timedelta(minutes=30)
                                }
                            }
                        )

                    # Step 4: Send email if not already in mapped list
                    if email not in existing_emails:
                        success, message = send_invitation_email_logic(
                            email, event_name, full_name, is_login=has_account, token=token
                        )
                        if not success:
                            email_failures.append({'email': email, 'reason': message})

                    admin_users.append({'email': email})
                    user_to_admin_map[email] = admin_id  # Track assignment
                if admin_users:
                    updated_admins.append({
                        'admin_id': admin_id,
                        'name': admin['name'],
                        'users': admin_users
                    })

            # Step 5: Update or create mapped event document
            if updated_admins:
                if existing_event:
                    # Create a merged version of assigned_admins
                    existing_admins_dict = {admin['admin_id']: admin for admin in existing_event.get('assigned_admins', [])}
                    
                    for new_admin in updated_admins:
                        admin_id = new_admin['admin_id']
                        if admin_id in existing_admins_dict:
                            # Admin already exists, merge users
                            existing_users = {user['email']: user for user in existing_admins_dict[admin_id].get('users', [])}
                            for new_user in new_admin['users']:
                                existing_users[new_user['email']] = new_user
                            
                            # Update with merged users list
                            existing_admins_dict[admin_id]['users'] = list(existing_users.values())
                        else:
                            # Add new admin
                            existing_admins_dict[admin_id] = new_admin
                    
                    merged_admins = list(existing_admins_dict.values())
                    
                    # Update existing document
                    mapped_events_collection.update_one(
                        {'_id': existing_event['_id']},
                        {
                            '$set': {
                                'assigned_admins': merged_admins,
                                'updated_at': datetime.now(timezone.utc)
                            }
                        }
                    )
                else:
                    # Create new document
                    mapped_events_collection.insert_one({
                        '_id': ObjectId(),
                        'event_name': event_name,
                        'event_id': event_id,
                        'assigned_admins': updated_admins,
                        'created_at': datetime.now(timezone.utc)
                    })

            # Get final state of assigned admins for response
            final_event = mapped_events_collection.find_one({'event_id': event_id})
            final_assigned_admins = final_event['assigned_admins'] if final_event else updated_admins
            
            response = {
                'message': 'Users assigned successfully',
                'event_id': event_id,
                'event_name': event_name,
                'assigned_admins': final_assigned_admins,
                'email_failures': email_failures
            }

            status = 200 if not email_failures else 207
            print(f"Response: {response}")
            return JsonResponse(response, status=status)
        except json.JSONDecodeError:
            print("JSON decode error in assign_users")
            return JsonResponse({'error': 'Invalid JSON format in request body'}, status=400)
        except Exception as e:
            print(f"Error in assign_users: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            print(traceback.format_exc())
            return JsonResponse({'error': f'Internal Server Error: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def remove_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            event_id = data.get('event_id')
            admin_id = data.get('admin_id')
            email = data.get('email')

            if not event_id or not admin_id or not email:
                return JsonResponse({'error': 'Missing event_id, admin_id, or email'}, status=400)

            # Find the event in mapped_events_collection
            event = mapped_events_collection.find_one({'event_id': event_id})
            if not event:
                return JsonResponse({'error': 'Event not found'}, status=404)

            # Find the admin and remove the email
            updated_admins = []
            updated = False
            for admin in event.get('assigned_admins', []):
                if admin['admin_id'] == admin_id:
                    # Filter out the email to remove
                    updated_users = [user for user in admin.get('users', []) if user['email'] != email]
                    if len(updated_users) < len(admin.get('users', [])):
                        updated = True
                    admin['users'] = updated_users
                updated_admins.append(admin)

            if not updated:
                return JsonResponse({'error': 'Email not found for the specified admin'}, status=400)

            # Update the event document
            mapped_events_collection.update_one(
                {'event_id': event_id},
                {
                    '$set': {
                        'assigned_admins': updated_admins,
                        'updated_at': datetime.now(timezone.utc)
                    }
                }
            )

            return JsonResponse({
                'message': f'Email {email} removed successfully',
                'event_id': event_id,
                'admin_id': admin_id
            }, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format in request body'}, status=400)
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return JsonResponse({'error': f'Internal Server Error: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

def generate_setup_token(admin_id, expiry_minutes=30):
    payload = {
        "admin_id": str(admin_id),
        "exp": datetime.utcnow() + timedelta(minutes=expiry_minutes),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def generate_setup_token_user(user_id, expiry_minutes=30):
    payload = {
        "user_id": str(user_id),
        "exp": datetime.utcnow() + timedelta(minutes=expiry_minutes),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def send_Admin_setup_email_logic(email: str, full_name: str, token: str) -> tuple[bool, str]:
    try:
        setup_link = f'http://localhost:5173/admin/reset-password?token={token}&email={email}'
        send_mail(
            subject='Set your password for your account',
            message=f"""
Hi {full_name},

Your Admin account has been created successfully.

Please click the following link to set your password: {setup_link}
This link will expire in 30 minutes.

Best regards,  
SuperAdmin Team
""",
            from_email="studentleaderdashboard@gmail.com",
            recipient_list=[email],
            fail_silently=False,
        )
        return True, "Password setup email sent successfully"
    except Exception as e:
        print(f"Email sending failed with error: {str(e)}")
        return False, f"Failed to send email: {str(e)}"

def send_student_setup_email_logic(email: str, full_name: str, token: str) -> tuple[bool, str]:
    try:
        setup_link = f'http://localhost:5173/student/setup-password?token={token}'
        send_mail(
            subject='Set your password for Student Portal',
            message=f"""
                    Hi {full_name},

                    Your student account has been created successfully.

                    Please click the following link to set your password: {setup_link}
                    This link will expire in 30 minutes.

                    Best regards,
                    SuperAdmin Team
            """,
            from_email="studentleaderdashboard@gmail.com",
            recipient_list=[email],
            fail_silently=False,
        )
        return True, "Password setup email sent successfully"
    except Exception as e:
        print(f"Email sending failed for {email}: {str(e)}")
        return False, f"Failed to send email: {str(e)}"

@csrf_exempt
def create_admin(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            name = data.get("name", "").strip()
            email = data.get("email", "").strip()
            print(f"Received data: name={name}, email={email}")

            if not all([name, email]):
                return JsonResponse({"error": "Name and email are required."}, status=400)

            if admin_collection.find_one({"email": email}):
                return JsonResponse({"error": "Admin with this email already exists."}, status=409)

            # STEP 1: Generate new Admin_ID in format "DT001", "DT002", ...
            last_admin = (
                admin_collection.find({"Admin_ID": {"$regex": "^DT[0-9]{3}$"}})
                .sort("Admin_ID", -1)
                .limit(1)
            )
            last_admin_id = next(last_admin, None)

            if last_admin_id and "Admin_ID" in last_admin_id:
                last_number = int(last_admin_id["Admin_ID"][2:])  # get the numeric part
                new_number = last_number + 1
            else:
                new_number = 1  # start from 1 if none exists

            new_admin_id = f"DT{new_number:03d}"  # pad with leading zeros

            # STEP 2: Insert new admin
            insert_result = admin_collection.insert_one({
                "name": name,
                "email": email,
                "Admin_ID": new_admin_id,
                "password": None,
                "created_at": datetime.now(),
                "status": "Active",
            })

            admin_id = insert_result.inserted_id

            # STEP 3: Generate token and update token-related fields
            token = generate_setup_token(admin_id)

            admin_collection.update_one(
                {"_id": admin_id},
                {
                    "$set": {
                        "setup_token": token,
                        "token_created_at": datetime.now()
                    }
                }
            )

            # STEP 4: Send email
            success, message = send_Admin_setup_email_logic(email, name, token)
            if not success:
                return JsonResponse({"error": message}, status=500)

            # STEP 5: Return the created admin
            created_admin = admin_collection.find_one({"_id": admin_id})
            created_admin["_id"] = str(created_admin["_id"])
            created_admin["created_at"] = created_admin["created_at"].isoformat()
            created_admin["token_created_at"] = created_admin["token_created_at"].isoformat()

            return JsonResponse(created_admin, status=200)

        except Exception as e:
            return JsonResponse({"error": f"Internal Server Error: {str(e)}"}, status=500)

    return JsonResponse({"error": "Method not allowed"}, status=405)

@csrf_exempt
def admin_reset_password(request):
    """
    Resets admin password using token and email verification.
    """
    print("Reset password request received")
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)
    print("Reset password request received")

    try:
        data = json.loads(request.body)
        token = data.get('token')
        email = data.get('email')
        new_password = data.get('new_password')
        print(f"Received data: token={token}, email={email}, new_password={new_password}")

        if not all([token, email, new_password]):
            return JsonResponse({"error": "Missing required fields"}, status=400)

        # Verify token and decode
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            print("JWT decoded successfully:", decoded)
            admin_id = decoded.get("admin_id")
        except jwt.ExpiredSignatureError:
            print("JWT has expired.")
            return JsonResponse({"error": "Token has expired"}, status=400)
        except jwt.InvalidTokenError as e:
            print("Invalid JWT:", str(e))
            return JsonResponse({"error": "Invalid token"}, status=400)
        
        admin = admin_collection.find_one({"_id": ObjectId(admin_id), "email": email})
        if not admin:
            return JsonResponse({"error": "Invalid admin credentials"}, status=404)

        # Update password and clear token info
        hashed_password = make_password(new_password)
        result = admin_collection.update_one(
            {"_id": ObjectId(admin_id)},
            {
                "$set": {"password": hashed_password, "status": "Active"},
                "$unset": {"setup_token": "", "token_created_at": ""}
            }
        )

        if result.modified_count == 0:
            return JsonResponse({"error": "Password update failed"}, status=500)

        return JsonResponse({"message": "Password reset successful"}, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def fetch_mapped_events(request, event_id):
    if request.method == 'GET':
        try:
            print(f"Fetching mapped events for event_id: {event_id}")
            mapped_event = mapped_events_collection.find_one({'event_id': event_id}, {
                '_id': 0,
                'event_id': 1,
                'event_name': 1,
                'assigned_admins': 1,
                'created_at': 1
            })
            if not mapped_event:
                print(f"No mapped event found for event_id: {event_id}")
                return JsonResponse({'error': 'No mapped event found for this event_id'}, status=404)

            mapped_event['created_at'] = mapped_event['created_at'].isoformat()
            print(f"Returning mapped event: {mapped_event}")
            return JsonResponse(mapped_event, status=200)
        except Exception as e:
            print(f"Error in fetch_mapped_events: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def validate_setup_token(request):
    """
    Validates an admin or student setup token.
    Returns 200 if valid, 400 if expired/invalid, or 404 if used/not found.
    """
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        token = request.GET.get("token")
        email = request.GET.get("email")  # Optional, for admin validation
        user_type = request.GET.get("type")  # 'admin' or 'student'

        if not token or not user_type or (user_type == "admin" and not email):
            return JsonResponse({"error": "Missing required parameters"}, status=400)

        # Decode the token
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            id_key = "admin_id" if user_type == "admin" else "user_id"
            entity_id = decoded.get(id_key)
            if not entity_id:
                return JsonResponse({"error": "Invalid token payload"}, status=400)
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token has expired"}, status=400)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=400)

        # Determine collection based on user_type
        collection = admin_collection  # Replace with your student collection

        # Query the entity
        query = {"_id": ObjectId(entity_id)}
        if user_type == "admin":
            query["email"] = email  # Ensure email matches for admin

        entity = collection.find_one(query)
        if not entity:
            return JsonResponse({"error": "Entity not found"}, status=404)

        # Check if token is still valid in the database (not used/cleared)
        stored_token = entity.get("setup_token")
        if not stored_token or stored_token != token:
            return JsonResponse({"error": "Token already used or invalid"}, status=404)

        # Token is valid
        return JsonResponse({"message": "Token is valid"}, status=200)

    except Exception as e:
        return JsonResponse({"error": f"Internal Server Error: {str(e)}"}, status=500)

@csrf_exempt
def totalscore_from_user(request):
    """
    Returns detailed breakdown of how a student's total score was calculated for a leaderboard event.
    Expects: event_id, student_name, student_email
    Returns: student info, total score, and detailed breakdown by level/task/subtask
    """
    if request.method != "POST":
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
        event_id = data.get('event_id')
        student_name = data.get('student_name')
        student_email = data.get('student_email')

        # Validate required parameters
        if not all([event_id, student_email]):
            return JsonResponse({
                'error': 'Missing required parameters: event_id and student_email are required'
            }, status=400)

        # Find the points data for the given event
        points_data = points_collection.find_one({"event_id": event_id})
        if not points_data:
            return JsonResponse({
                'error': f'No scoring data found for event_id: {event_id}'
            }, status=404)

        # Find the student's score data within the points collection
        student_score_data = None
        found_admin = None

        for admin in points_data.get("assigned_to", []):
            for mark in admin.get("marks", []):
                # Match by email (primary) and optionally by name for validation
                if mark.get("student_email") == student_email:
                    if student_name and mark.get("student_name") != student_name:
                        # If student_name is provided but doesn't match, skip this entry
                        continue
                    student_score_data = mark
                    found_admin = admin
                    break
            if student_score_data:
                break

        if not student_score_data:
            return JsonResponse({
                'error': f'No scoring data found for student with email: {student_email}'
            }, status=404)

        # Calculate total score and build detailed breakdown
        total_score = 0
        levels_breakdown = []

        for level_idx, level in enumerate(student_score_data.get("score", [])):
            level_total = 0
            tasks_breakdown = []

            for task_idx, task in enumerate(level.get("task", [])):
                task_total = 0
                subtasks_breakdown = []

                # Handle both direct task points and subtask points
                if "points" in task:
                    # Direct task points (no subtasks)
                    task_points = task.get("points", 0)
                    task_total += task_points
                    subtasks_breakdown.append({
                        "subtask_name": f"Task {task_idx + 1}",
                        "points": task_points
                    })
                
                # Handle subtask points if they exist
                for subtask_idx, subtask in enumerate(task.get("subtasks", [])):
                    subtask_points = subtask.get("points", 0)
                    task_total += subtask_points
                    subtasks_breakdown.append({
                        "subtask_name": subtask.get("name", f"Subtask {subtask_idx + 1}"),
                        "points": subtask_points
                    })

                if task_total > 0 or subtasks_breakdown:  # Only include tasks with points or subtasks
                    tasks_breakdown.append({
                        "task_name": task.get("task_name", f"Task {task_idx + 1}"),
                        "task_total": task_total,
                        "subtasks": subtasks_breakdown
                    })

                level_total += task_total

            if level_total > 0 or tasks_breakdown:  # Only include levels with points or tasks
                levels_breakdown.append({
                    "level_name": f"Level {level_idx + 1}",
                    "level_total": level_total,
                    "tasks": tasks_breakdown
                })

            total_score += level_total

        # Prepare response with student info and detailed breakdown
        response_data = {
            "success": True,
            "student_info": {
                "name": student_score_data.get("student_name", student_name or "Unknown"),
                "email": student_email,
                "total_score": total_score
            },
            "score_breakdown": {
                "total_score": total_score,
                "levels": levels_breakdown
            },
            "event_info": {
                "event_id": event_id,
                "admin_assigned": found_admin.get("admin_name", "Unknown") if found_admin else "Unknown"
            }
        }

        return JsonResponse(response_data, status=200)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format in request body'}, status=400)
    except Exception as e:
        return JsonResponse({'error': f'Server error: {str(e)}'}, status=500)