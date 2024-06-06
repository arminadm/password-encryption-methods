from rest_framework import status
from django.utils.translation import gettext_lazy as _
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.base_user import BaseUserManager
from website.tools.exception import CustomException


class UserManager(BaseUserManager):
    """
    Custom user model manager where phone number is the unique
    identifiers for authentication.
    """
    def create_user(self, phone, password, **extra_fields):
        """
        Create and save a user with the given phone, password.
        """
        # set is_active to True so we can authenticate this user later
        extra_fields.setdefault("is_active", True)
        if extra_fields.get("is_active") is not True:
            raise ValueError()

        if not password:
            raise CustomException(
                "ساخت حساب بدون وارد کردن پسورد امکان پذیر نمیباشد",
                "detail",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = self.model(phone=phone, **extra_fields)
            user.set_password(password)
            user.save()
            return user

        except Exception as e:
            raise CustomException(
                e,
                "detail",
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
            )
        

    def create_superuser(self, phone, password, **extra_fields):
        """
        Create and save a SuperUser with the given phone and password.
        """
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_verified", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError()
        if extra_fields.get("is_superuser") is not True:
            raise ValueError()
        if extra_fields.get("is_active") is not True:
            raise ValueError()
        return self.create_user(phone, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    # Data
    phone = models.BigIntegerField(unique=True, null=False, blank=False)
    sha1_password = models.CharField(max_length=200, null=False, blank=False)
    
    # Django required fields
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # system information
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "phone"

    objects = UserManager()

    def __str__(self):
        return f"User obj: {self.id}-{self.phone}"
    
    