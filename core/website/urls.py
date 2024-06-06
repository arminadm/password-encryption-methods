from django.urls import path
from .views import SignupView, LoginStep1View, LoginStep2View


urlpatterns = [
   path("signup/", SignupView.as_view(), name="signup"),
   path("login/step1/", LoginStep1View.as_view(), name="login-step1"),
   path("login/step2/", LoginStep2View.as_view(), name="login-step2"),
]
