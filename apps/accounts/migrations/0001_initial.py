"""
apps/accounts initial migration — Organization + User (custom AbstractUser)
"""
import uuid
import django.contrib.auth.models
import django.contrib.auth.validators
import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        # --- Organization (must come first as User FKs to it) ---
        migrations.CreateModel(
            name='Organization',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=200, unique=True)),
                ('slug', models.SlugField(max_length=200, unique=True)),
                ('plan_tier', models.CharField(
                    choices=[('FREE', 'Free'), ('PRO', 'Professional'), ('ENTERPRISE', 'Enterprise')],
                    default='FREE',
                    max_length=20,
                )),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Organization',
                'verbose_name_plural': 'Organizations',
                'ordering': ['name'],
            },
        ),

        # --- User (custom AbstractUser) ---
        migrations.CreateModel(
            name='User',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, verbose_name='superuser status')),
                ('username', models.CharField(
                    error_messages={'unique': 'A user with that username already exists.'},
                    max_length=150,
                    unique=True,
                    validators=[django.contrib.auth.validators.UnicodeUsernameValidator()],
                    verbose_name='username',
                )),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('is_staff', models.BooleanField(default=False, verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('organization', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='members',
                    to='accounts.organization',
                )),
                ('role', models.CharField(
                    choices=[
                        ('SUPERADMIN', 'Super Admin'),
                        ('ADMIN', 'Admin'),
                        ('ANALYST', 'Analyst'),
                        ('VIEWER', 'Viewer'),
                    ],
                    default='VIEWER',
                    max_length=20,
                )),
                ('api_key', models.UUIDField(default=uuid.uuid4, unique=True, db_index=True)),
                ('api_key_active', models.BooleanField(default=True)),
                ('bio', models.TextField(blank=True)),
                ('avatar', models.ImageField(blank=True, null=True, upload_to='avatars/')),
                ('timezone', models.CharField(default='UTC', max_length=50)),
                ('last_login_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('groups', models.ManyToManyField(
                    blank=True,
                    related_name='user_set',
                    related_query_name='user',
                    to='auth.group',
                    verbose_name='groups',
                )),
                ('user_permissions', models.ManyToManyField(
                    blank=True,
                    related_name='user_set',
                    related_query_name='user',
                    to='auth.permission',
                    verbose_name='user permissions',
                )),
            ],
            options={
                'verbose_name': 'User',
                'verbose_name_plural': 'Users',
                'ordering': ['email'],
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),

        # Indexes
        migrations.AddIndex(
            model_name='user',
            index=models.Index(fields=['organization', 'role'], name='accounts_user_org_role_idx'),
        ),
        migrations.AddIndex(
            model_name='user',
            index=models.Index(fields=['api_key'], name='accounts_user_api_key_idx'),
        ),
    ]
