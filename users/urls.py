from . import views
from django.contrib.auth import views as auth_views
from users.views import CustomLoginView
from users.forms import LoginForm
from django.urls import path, re_path
from .views import unblock_username_view


app_name = "users"
urlpatterns = [
    path('login/', CustomLoginView.as_view(redirect_authenticated_user=True, template_name='accounts/login.html',
                                           authentication_form=LoginForm), name='login'),

    path('signup/', views.signup, name="signup"),
    path("logout/", views.logout_view, name="logout"),
    path('users/', views.userspage, name="users"),
    path('accessattempts/', views.SystemAccessAttempts, name="accessattempts"),
    path('blockedusers/', views.BlockedUsers, name="blockedusers"),
    # path("blocks/username/<path:username>/unblock",unblock_username_view,name="defender_unblock_username_view"),

    path('unblockuser/<path:username>/',
         views.unblock_username_view, name="unblockuser"),

    path('edituser/<int:pk>/', views.EditUser, name="edituser"),

    path('userprofile/', views.UserProfile, name="userprofile"),
    path('signature_upload/<int:pk>/', views.SignatureUpload, name="signature_upload"),

    path('password/', views.change_password, name="change_password"),

    path('activate/<int:user_id>/', views.user_activate, name="activate_user"),
    path('deactivate/<int:user_id>/',
         views.user_deactivate, name="deactivate_user"),
    path('activate/<slug:uidb64>/<slug:token>/',
         views.activate, name='activate'),

    # PASSWORD RESET PATHS
    # venv/lib/python3.8/site-packages/django/contrib/admin/templates/registration

    path('reset_password/',
         auth_views.PasswordResetView.as_view(
             template_name="password_reset.html"),
         name="reset_password"),

    path('reset_password_sent/',
         auth_views.PasswordResetDoneView.as_view(
             template_name="password_reset_sent.html"),
         name="password_reset_done"),

    path('reset/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(
             template_name="password_reset_form.html"),
         name="password_reset_confirm"),

    path('reset_password_complete/',
         auth_views.PasswordResetCompleteView.as_view(
             template_name="password_reset_done.html"),
         name="password_reset_complete"),

     #forgot password
     path("forgotpassword", views.password_reset_request, name="forgotpassword")

]
