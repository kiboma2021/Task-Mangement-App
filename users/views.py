from django.contrib.auth.views import LoginView
from django.contrib.auth import login, authenticate, logout,get_user_model
from django.shortcuts import render, redirect, get_object_or_404, HttpResponse, HttpResponseRedirect
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_str
from django.db import IntegrityError
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.utils.crypto import get_random_string
from .forms import SignUpForm,LoginForm,UserEditForm,UserSignatureForm
from .tokens import account_activation_token
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode
from django.template.loader import render_to_string
from datetime import date, timedelta
import smtplib
from email.mime.text import MIMEText
from defender.models import AccessAttempt
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.urls import reverse

from .utils import get_blocked_ips, get_blocked_usernames, unblock_ip, unblock_username

from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordResetForm, SetPasswordForm
from django.core.files.storage import FileSystemStorage

from django.db.models.query_utils import Q
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail


User =get_user_model()

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    # checking if the user exists, if the token is valid.
    if user is not None and account_activation_token.check_token(user, token):
        # if valid set active true 
        user.is_active = True
        # set signup_confirmation true
        user.profile.signup_confirmation = True
        user.save()
        login(request, user)
        return redirect('dashboard:home')
    else:
        return render(request, 'activation_invalid.html')

@login_required(login_url='users:login')
def signup(request):
    if request.method  == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            password =get_random_string(length=8)
            user.set_password(password)
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            subject = 'Insurance Employee Task Management'
            message = render_to_string('ICT/email_validation.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'password':password,
                # method will generate a hash value with user related data
                'token': account_activation_token.make_token(user),
            })
            user.email_user(subject, message)
            return redirect('users:users')

    else:
        form = SignUpForm()
    return render(request, 'ICT/user_registration.html', {'form': form})


@login_required(login_url='users:login')
def EditUser(request,pk):

    filteruser=User.objects.get(id=pk)
    form=UserEditForm(instance=filteruser)

    if request.method  == 'POST':
        form = UserEditForm(request.POST,instance=filteruser)
        if form.is_valid():
            filteruser = form.save(commit=False)
            filteruser.save()
            current_site = get_current_site(request)
            subject = 'XYZ Insurance TMS'

            message = render_to_string('ICT/email_edituser.html', {
                'filteruser': filteruser,
            })

            filteruser.email_user(subject, message)

            return redirect('users:users')

    context={'form':form,'filteruser':filteruser}    
    return render(request, 'ICT/user_registration_edit.html',context)


@login_required(login_url='users:login')
def userspage(request):
    users=User.objects.all()
    total_users=users.count()

    context={'total_users':total_users,'users':users}      
    return render (request, 'ICT/users.html',context)


@login_required(login_url='users:login')
def SystemAccessAttempts(request):

    access_logs=AccessAttempt.objects.all()
    successful_logs=AccessAttempt.objects.filter(login_valid=True).count()
    failed_logs=AccessAttempt.objects.filter(login_valid=False).count()

    print("-----")
    print(access_logs)

    context={'access_logs':access_logs,'successful_logs':successful_logs,'failed_logs':failed_logs }      
    return render (request, 'ICT/users_access_attempts.html',context)



@login_required(login_url='users:login')
def BlockedUsers(request):
    blocked_username_list = get_blocked_usernames()

    context={'blocked_username_list':blocked_username_list }      
    return render (request, 'ICT/users_blocked.html',context)


@login_required(login_url='users:login')
def unblock_username_view(request, username):
    """ unblock the given username """
    if request.method == "POST":
        unblock_username(username)
    return render (request, 'ICT/users_blocked.html')


class CustomLoginView(LoginView):
    form_class = LoginForm

    def form_valid(self, form):
        remember_me = form.cleaned_data.get('remember_me')
        if not remember_me:
            self.request.session.set_expiry(0)
            self.request.session.modified = True
        return super(CustomLoginView, self).form_valid(form)


def logout_view(request):
    logout(request)
    return redirect('users:login')


def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Your password was successfully updated!')
            return redirect("/")
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'ICT/change_password.html', {
        'form': form
    })



#@admin_only
def user_deactivate(request, user_id):
    user = User.objects.get(id=user_id)
    user.is_active = False
    user.save()
    messages.success(request, "User account has been successfully deactivated!")
    return redirect('users:users')
    #return render (request, 'users.html')

#@login_required(login_url='login')
#@allowed_users(allowed_roles=['admin','claims'])
def user_activate(request, user_id):
    user = User.objects.get(id=user_id)
    user.is_active = True
    user.save()
    messages.success(request, "User account has been successfully activated!")
    return redirect('users:users')
    #return render (request, 'users.html')



class UserPasswordResetForm(SetPasswordForm):
    """Change password form."""
    new_password1 = forms.CharField(label='Password',
        help_text="<ul class='errorlist text-muted'><li>Your password can 't be too similar to your other personal information.</li><li>Your password must contain at least 8 characters.</li><li>Your password can 't be a commonly used password.</li> <li>Your password can 't be entirely numeric.<li></ul>",
        max_length=100,
        required=True,
        widget=forms.PasswordInput(
        attrs={
            'class': 'form-control',
            'placeholder': 'password',
            'type': 'password',
            'id': 'user_password',
        }))

    new_password2 = forms.CharField(label='Confirm password',
        help_text=False,
        max_length=100,
        required=True,
        widget=forms.PasswordInput(
        attrs={
            'class': 'form-control',
            'placeholder': 'confirm password',
            'type': 'password',
            'id': 'user_password',
        }))


class UserForgotPasswordForm(PasswordResetForm):
    """User forgot password, check via email form."""
    email = forms.EmailField(label='Email address',
        max_length=254,
        required=True,
        widget=forms.TextInput(
         attrs={'class': 'form-control',
                'placeholder': 'email address',
                'type': 'text',
                'id': 'email_address'
                }
        ))


@login_required(login_url='users:login')
def UserProfile(request):

    users=User.objects.filter(username=request.user.username)

    context={'users':users,}
    return render (request, 'ICT/user_profile.html',context)


@login_required(login_url='users:login')
def SignatureUpload(request,pk):
    if pk:
        users=User.objects.get(id=pk)
        form=UserSignatureForm(instance=users)
    else:
        form=UserSignatureForm(request.POST, request.FILES)
    if request.method=='POST':
        form=UserSignatureForm(request.POST,request.FILES, instance=users)
        if form.is_valid():
            form.save()
            return redirect('users:userprofile')
        else:
            messages.error(request, 'Please correct the error below.')
            print("--error----")

    context={'form':form,'users':users} 

    return render(request, 'ICT/signature_form.html',context)


def password_reset_request(request):
    if request.method == "POST":
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = User.objects.filter(Q(email=data))
            if associated_users.exists():
                for user in associated_users:
                    password =get_random_string(length=8)
                    user.set_password(password)
                    user.save()

                    msg = MIMEText(render_to_string('ICT/forgot_password.html', {
                        "email":user.email,
                        'domain':'127.0.0.1:8000',
                        'site_name': 'Website',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        'password':password,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',

                    }))


                    to_email=user.email
                    from_email="LSP_System@libertylife.co.ke"
                    
                    msg['Subject']='Forgot Password'
                    msg['From']='LSP_System@libertylife.co.ke'
                    msg['To']=to_email

                    server = smtplib.SMTP("10.235.130.162", 587)
                    server.connect("10.235.130.162", 587)

                    server.sendmail(from_email, to_email, msg.as_string())
                    
                    return redirect('dashboard:home')
                    
    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="ICT/password_reset.html", context={"password_reset_form":password_reset_form})