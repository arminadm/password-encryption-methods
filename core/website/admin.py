from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from website.models import User

# Register your models here.
class CustomUserAdmin(UserAdmin):
    model = User
    list_display = [
        "id",
        "phone",
        "sha1_password",
        "is_active",
        "is_verified",
        "is_staff",
        "is_superuser",
        "created_date",
        "updated_date",
    ]
    list_filter = [
        "is_active",
        "is_verified",
        "is_staff",
        "is_superuser",
    ]
    ordering = ["-created_date"]
    fieldsets = (
        ("Authentication", {"fields": ("phone", "sha1_password")}),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_verified",
                    "is_staff",
                    "is_superuser",
                )
            },
        ),
        ("Group permissions", {"fields": ("groups", "user_permissions")}),
        ("Important date", {"fields": ("last_login",)}),
    )
    add_fieldsets = (
        (
            "User info",
            {
                "classes": ("wide",),
                "fields": (
                    "phone",
                    "password",
                    "password1",
                    "password2",
                    "is_active",
                    "is_verified",
                    "is_staff",
                    "is_superuser",
                ),
            },
        ),
    )
admin.site.register(User, CustomUserAdmin)