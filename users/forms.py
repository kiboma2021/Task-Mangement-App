from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm 


from .models import User

class SignUpForm(forms.ModelForm):

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'role', 'department', 'phone_number',)
        #exclude =('password', 'password1')


class UserEditForm(forms.ModelForm):

    class Meta:
        model = User
        fields = ('first_name','last_name','role','phone_number','is_active')


class LoginForm(AuthenticationForm):
    username = forms.CharField(max_length=100,
                               required=True,
                               widget=forms.TextInput(attrs={'placeholder': 'Username',
                                                             'class': 'form-control',
                                                             }))
    password = forms.CharField(max_length=50,
                               required=True,
                               widget=forms.PasswordInput(attrs={'placeholder': 'Password',
                                                                 'class': 'form-control',
                                                                 'data-toggle': 'password',
                                                                 'id': 'password',
                                                                 'name': 'password',
                                                                 }))
    remember_me = forms.BooleanField(required=False)

    class Meta:
        model = User
        fields = ['username', 'password', 'remember_me']


class UserSignatureForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('signature',)