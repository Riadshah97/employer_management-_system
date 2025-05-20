from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(
        unique=True,
        db_index=True,
        verbose_name=_("Email Address"),
    )
    username = models.CharField(
        max_length=30,
        unique=True,
        verbose_name=_("Username"),
    )
    first_name = models.CharField(
        max_length=30,
        blank=True,
        verbose_name=_("First Name"),
    )
    last_name = models.CharField(
        max_length=30,
        blank=True,
        verbose_name=_("Last Name"),
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name=_("Active"),
    )
    is_staff = models.BooleanField(
        default=False,
        verbose_name=_("Staff Status"),
    )
    date_joined = models.DateTimeField(
        default=timezone.now,
        verbose_name=_("Date Joined"),
    )

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    class Meta:
        db_table = "identity_users"
        verbose_name = _("User")
        verbose_name_plural = _("Users")

    def __str__(self):
        return self.email

class Employer(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='employers',
        verbose_name=_("User"),
    )
    company_name = models.CharField(
        max_length=100,
        verbose_name=_("Company Name"),
    )
    contact_person_name = models.CharField(
        max_length=100,
        verbose_name=_("Contact Person Name"),
    )
    email = models.EmailField(
        verbose_name=_("Email Address"),
    )
    phone_number = models.CharField(
        max_length=20,
        verbose_name=_("Phone Number"),
    )
    address = models.TextField(
        verbose_name=_("Address"),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Created At"),
    )

    class Meta:
        db_table = "employers"
        verbose_name = _("Employer")
        verbose_name_plural = _("Employers")

    def __str__(self):
        return self.company_name
