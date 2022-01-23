import random
import binascii
import datetime
import os
from django.db import models
from django.db.models.signals import post_save
from django.utils.timezone import now
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, UserManager
from django.utils import timezone
from django.conf import settings
from django.utils.crypto import get_random_string
from django.dispatch import receiver
from django.core.mail import send_mail
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.timezone import localtime


DEPARTMENT=(
        ('Customer Service','Customer Service'),      
        ('Claims','Claims'),
        ('Finance','Finance'),       
        ('Premium Processing','Premium Processing'),   
        ('Pensions','Pensions'),   
        ('Business Operations','Business Operations'),   
        ('Group Life Underwriting','Group Life Underwriting'),       
        ('Retail Underwriting','Retail Underwriting'),     
  
    )
ROLE=(
        ('Analyst','Analyst'),      
        ('Specialist','Specialist'),
        ('Manager','Manager'),    
        ('General Manager','General Manager'),   
        ('Managing Director','Managing Director'),   
        ('CEO','CEO'),       
    )

class User(AbstractBaseUser, PermissionsMixin):
    file_prepend = "users/profile_pics"
    username = models.CharField(max_length=100, unique=True)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    email = models.EmailField(max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(("date joined"), auto_now_add=True)
    date_updated= models.DateField(auto_now=True)
    department = models.CharField(max_length=200, null=True, choices=DEPARTMENT)
    role = models.CharField(max_length=200, null=True, choices=ROLE)
    phone_number = models.CharField(max_length=20, null=True)
    signature=models.FileField(blank=True,upload_to ='profile_pics/')


    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = [
        "email",
    ]

    objects = UserManager()

    def get_short_name(self):
        return self.username

    def email_user(self, *args, **kwargs):
        send_mail(
            '{}'.format(args[0]),
            '{}'.format(args[1]),
            '{}'.format(settings.DEFAULT_FROM_EMAIL),
            [self.email],
            fail_silently=False,
        )


    def get_full_name(self):
        full_name = None
        if self.first_name or self.last_name:
            full_name = self.first_name + " " + self.last_name
        elif self.username:
            full_name = self.username
        else:
            full_name = self.email
        return full_name

    def __str__(self):
        return self.username


     #PASSWORD VALIDATOR MODEL

    def __init__(self, *args, **kwargs):
        super(User, self).__init__(*args, **kwargs)
        self.original_password = self.password

    def save(self, *args, **kwargs):
        super(User, self).save(*args, **kwargs)
        if self._password_has_been_changed():
            CustomUserPasswordHistory.remember_password(self)

    def _password_has_been_changed(self):
        return self.original_password != self.password


    class Meta:
        ordering = ["username"]


class CustomUserPasswordHistory(models.Model):
    username = models.ForeignKey(User, on_delete=models.CASCADE)
    old_pass = models.CharField(max_length=128)
    pass_date = models.DateTimeField()

    @classmethod
    def remember_password(cls, user):
        cls(username=user, old_pass=user.password, pass_date=localtime()).save()


class AccessAttempt(models.Model):
    """ Access Attempt log """

    user_agent = models.CharField(max_length=255,)
    ip_address = models.GenericIPAddressField(verbose_name="IP Address", null=True,)
    username = models.CharField(max_length=255, null=True,)
    http_accept = models.CharField(verbose_name="HTTP Accept", max_length=1025,)
    path_info = models.CharField(verbose_name="Path", max_length=255,)
    attempt_time = models.DateTimeField(auto_now_add=True,)
    login_valid = models.BooleanField(default=False,)

    class Meta:
        ordering = ["-attempt_time"]

    def __str__(self):
        """ unicode value for this model """
        return "{0} @ {1} | {2}".format(
            self.username, self.attempt_time, self.login_valid
        )

def generate_key():
    return binascii.hexlify(os.urandom(8)).decode()

class APISettings(models.Model):
    title = models.CharField(max_length=1000)
    apikey = models.CharField(max_length=16, blank=True)
    website = models.URLField(max_length=255, default="")
    
    created_by = models.ForeignKey(
        User, related_name="settings_created_by", on_delete=models.SET_NULL, null=True
    )
    created_on = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_on",)

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if not self.apikey or self.apikey is None or self.apikey == "":
            self.apikey = generate_key()
        super(APISettings, self).save(*args, **kwargs)


class Profile(models.Model):
    """ this model is used for activating the user within a particular expiration time """
    user = models.OneToOneField(
        User, related_name="profile", on_delete=models.CASCADE
    )  # 1 to 1 link with Django User
    activation_key = models.CharField(max_length=50)
    key_expires = models.DateTimeField()
    signup_confirmation = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        """ by default the expiration time is set to 12 hours """
        self.key_expires = timezone.now() + datetime.timedelta(hours=12)
        super(Profile, self).save(*args, **kwargs)


@receiver(post_save, sender=User)
def update_profile_signal(sender, instance, created, **kwargs):
    if created:
        key=get_random_string(length=32)
        Profile.objects.create(user=instance,activation_key=key)
        #instance.profile.save()


class PhoneOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=254, blank=True, null=True)
    otp = models.CharField(max_length=9, blank=True, null=True)
    count = models.IntegerField(default=0, help_text='Number of opt_sent')
    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.CharField(max_length=200, default="Authentication Verifier")
    expiry = models.DateTimeField(null=True)
    validated = models.BooleanField(default=False,
                                    help_text='if it is true, that means user have validate opt correctly in seconds')

    def __str__(self):
        return str(self.user.phone_number) + ' is sent ' + str(self.otp)

    def is_valid(self):
        if self.expiry < now():
            return False
        return True


def generate_otp(sender, instance, created, **kwargs):
    if created:
        '''generate a 6-digit with expiry in 5 minutes'''
        if not instance.otp:
            otp = random.randrange(1, 1000000)
            expiry = now() + datetime.timedelta(minutes=5)
            instance.otp = otp
            instance.expiry = expiry
            instance.save()

post_save.connect(sender=PhoneOTP, receiver=generate_otp)