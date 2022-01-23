# Generated by Django 4.0.1 on 2022-01-23 14:46

from django.conf import settings
import django.contrib.auth.models
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(max_length=100, unique=True)),
                ('first_name', models.CharField(max_length=150)),
                ('last_name', models.CharField(max_length=150)),
                ('email', models.EmailField(max_length=255, unique=True)),
                ('is_active', models.BooleanField(default=True)),
                ('date_joined', models.DateTimeField(auto_now_add=True, verbose_name='date joined')),
                ('date_updated', models.DateField(auto_now=True)),
                ('department', models.CharField(choices=[('Customer Service', 'Customer Service'), ('Claims', 'Claims'), ('Finance', 'Finance'), ('Premium Processing', 'Premium Processing'), ('Pensions', 'Pensions'), ('Business Operations', 'Business Operations'), ('Group Life Underwriting', 'Group Life Underwriting'), ('Retail Underwriting', 'Retail Underwriting')], max_length=200, null=True)),
                ('role', models.CharField(choices=[('Analyst', 'Analyst'), ('Specialist', 'Specialist'), ('Manager', 'Manager'), ('General Manager', 'General Manager'), ('Managing Director', 'Managing Director'), ('CEO', 'CEO')], max_length=200, null=True)),
                ('phone_number', models.CharField(max_length=20, null=True)),
                ('signature', models.FileField(blank=True, upload_to='profile_pics/')),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.Group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'ordering': ['username'],
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='AccessAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_agent', models.CharField(max_length=255)),
                ('ip_address', models.GenericIPAddressField(null=True, verbose_name='IP Address')),
                ('username', models.CharField(max_length=255, null=True)),
                ('http_accept', models.CharField(max_length=1025, verbose_name='HTTP Accept')),
                ('path_info', models.CharField(max_length=255, verbose_name='Path')),
                ('attempt_time', models.DateTimeField(auto_now_add=True)),
                ('login_valid', models.BooleanField(default=False)),
            ],
            options={
                'ordering': ['-attempt_time'],
            },
        ),
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('activation_key', models.CharField(max_length=50)),
                ('key_expires', models.DateTimeField()),
                ('signup_confirmation', models.BooleanField(default=False)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='PhoneOTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone_number', models.CharField(blank=True, max_length=254, null=True)),
                ('otp', models.CharField(blank=True, max_length=9, null=True)),
                ('count', models.IntegerField(default=0, help_text='Number of opt_sent')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('message', models.CharField(default='Authentication Verifier', max_length=200)),
                ('expiry', models.DateTimeField(null=True)),
                ('validated', models.BooleanField(default=False, help_text='if it is true, that means user have validate opt correctly in seconds')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='CustomUserPasswordHistory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('old_pass', models.CharField(max_length=128)),
                ('pass_date', models.DateTimeField()),
                ('username', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='APISettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=1000)),
                ('apikey', models.CharField(blank=True, max_length=16)),
                ('website', models.URLField(default='', max_length=255)),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='settings_created_by', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('-created_on',),
            },
        ),
    ]