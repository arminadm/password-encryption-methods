from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from core.settings import PASS_SALT
from .serializers import SignupSerializer, LoginStep1Serializer, LoginStep2Serializer
from website.tools.auth import generate_jwt_for


# Create your views here.
class SignupView(GenericAPIView):
    serializer_class = SignupSerializer
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        data = generate_jwt_for(user)
        return Response(data, status=status.HTTP_201_CREATED)
    

class LoginStep1View(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginStep1Serializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        challenge = serializer.get_challenge()
        return Response(
            {
                "challenge": challenge,
                "salt": PASS_SALT
            },
            status=status.HTTP_200_OK
        )
        

class LoginStep2View(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginStep2Serializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = serializer.check_credentials()
        return Response(result, status=status.HTTP_200_OK)
        