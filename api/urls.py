from django import views
from django import views
from django.urls import path
from .views import *
from .admins import *
from .superadmin import *
from .students import *


urlpatterns = [


    #Admin URLs
    path('admin/signin/', admin_signin, name='admin_signin'),
    path('admin/reset-password/', admin_reset_password, name='reset_password'),
    path('admin/list-assigned-students/', list_assigned_students, name='list_assigned_students'),
    path('admin/fetch_grouped_tasks/', fetch_tasks_grouped_by_event, name='fetch_grouped_tasks'),
    path('fetch_grouped_tasks/', fetch_tasks_grouped_by_event, name='fetch_grouped_tasks'),
    path('admin/get_events/', get_admin_events, name='get_events'),
    path('admin/get_tasks/<str:event_id>/',get_event_task_by_admin, name='get_event_task_by_admin'),
    path('admin/getstudent_task_report/<str:event_id>/<str:admin_id>/', get_students_by_event_and_admin, name='get_student_task_report'),    
    path("admin/manage_task_points/<str:event_id>/<str:task_id>/",manage_task_points,name="manage_task_points"),
    path("admin/get_students_details/<str:event_id>/", get_students_details, name="get_students_details"),
    path("admin/leaderboard_points/<str:event_id>/", leaderboard, name="get_leaderboard_points"),
    path('admin/forgot-password/', forgot_password, name='forgot_password'),
    path('admin/validate-reset-token/', validate_reset_token, name='validate_reset_token'),
    # path('admin/reset-password1/', reset_password, name='reset_password'),
    path("admin/reset-password-for-forgot-password/", reset_password_for_forgot_password, name="reset_password_for_forgot_password"),
    #Student URLs
    path('student/signup/', student_signup, name='student_signup'),
    path('student/signup-direct/', student_signup_direct, name='student_signup_direct'),
    path('student/login/', student_login, name='student_login'),
    path('Student/send-reset-link/', send_reset_link, name='student_send_reset_link'),
    path('Student/reset-password/', reset_password, name='student_reset_password'),
    path('student/profile/', get_student_profile, name='get_student_profile'),
    path('student/get-data/', get_student_data, name='get_student_data'),
    path('student/dashboard/', get_student_dashboard_data, name='get_student_dashboard_data'),
    path('student/set-password/', set_password, name='set_password'),
    path('student/validate-password-setup-token/', validate_password_setup_token, name='validate_password_setup_token'),
    path('student/tasks/', get_student_tasks, name='get_student_tasks'),
    path('student/get-tasks/', get_student_events, name='get_student_events'),
    path('student/task-details/',get_event_details,name='get_event_details'),
    path('student/student-streaks/',student_attendance, name='student_attendance'),
    path('level/<str:level_id>/tasks/', get_tasks_by_level_id, name='get_tasks_by_level_id'),
    path('student/milestones/', student_milestones, name='student_milestones'),
    path('student/leaderboard/', get_leaderboard_data, name='get_leaderboard_data'),
    path('student/events/<str:event_id>/points/', get_student_points_by_event, name='get_student_points_by_event'),
    path("student/validate-reset-token/", validate_reset_token, name="validate_reset_token"),
    # path("student/validate-student-signup-token/", validate_student_signup_token, name="validate_student_signup_token"),
    path("student/check-student-signup-token/", check_token_validity, name="check_student_signup_token"),
    path("student/total_points_of_user/", total_points_of_user, name="total_points_of_user"),
    path('student/leaderboard-by-level/', get_leaderboard_by_level, name='get_leaderboard_by_level'),
    path("student/points_by_eventid/", Students_point_by_eventid, name="Students_point_by_eventid"),


    #Superadmin URLs
    path('superadmin/login/', superadmin_login_view, name='superadmin_login'),
    # path('superadmin/send-email/', superadmin_send_email, name='superadmin_send_email'),
    path('superadmin/create_task/', create_task, name='create_task'),
    path('bulk_upload/', bulk_upload_students, name='bulk_upload_students'),
    path('superadmin/create-admin/', create_admin, name='create_admin'),
    path('superadmin/fetch_all_tasks/', fetch_all_tasks_for_superadmin, name='fetch_all_tasks'),
    path("superadmin/get_admins/", get_admins, name='get_all_admins'),
    path('superadmin/assign_users/', assign_users, name='assign_users'),
    path('superadmin/fetch_mapped_events/<str:event_id>/', fetch_mapped_events, name='fetch_mapped_events'),
    path('superadmin/remove_user/', remove_user, name='remove_user'),
    path('superadmin/update_task/<str:event_id>/', update_task, name='update_task'),
    path('superadmin/delete_task/<str:event_id>/', delete_task, name='delete_task'),
    path("superadmin/validate-setup-token/", validate_setup_token, name="validate_setup_token"),

]