from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from core.settings import PASS_SALT
from website.tools.auth import generate_jwt_for
from .serializers import (
    SignupSerializer, LoginStep1Serializer, LoginStep2Serializer,
    EncryptionSHA1Serializer, EncryptionSHA2Serializer, EncryptionMD5Serializer,
    EncryptionAESSerializer, DecryptionAESSerializer, EncryptionDESSerializer,
    DecryptionDESSerializer, EncryptionElgamalSerializer, DecryptionElgamalSerializer,
    EncryptionRSASerializer, EncryptionHMACMD5Serializer, EncryptionHMACSHA1Serializer,
    EncryptionHMACSHA256Serializer, DecryptionRSASerializer
)


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
        challenge, pass_salt = serializer.get_challenge()
        return Response(
            {
                "challenge": challenge,
                "salt": pass_salt
            },
            status=status.HTTP_200_OK
        )
        
        
# class LoginStep1View(GenericAPIView):
#     permission_classes = [AllowAny]
#     serializer_class = LoginStep1Serializer
    
#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         challenge = serializer.get_challenge()
#         return Response(
#             {
#                 "challenge": challenge,
#                 "salt": PASS_SALT
#             },
#             status=status.HTTP_200_OK
#         )

class LoginStep2View(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginStep2Serializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = serializer.check_credentials()
        return Response(result, status=status.HTTP_200_OK)
    

class EncryptionSHA1View(GenericAPIView):
    serializer_class = EncryptionSHA1Serializer
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        cipher = serializer.encrypt()
        return Response({"result": cipher}, status=status.HTTP_200_OK)
    

class EncryptionSHA2View(EncryptionSHA1View):
    serializer_class = EncryptionSHA2Serializer
        

class EncryptionMD5View(EncryptionSHA1View):
    serializer_class = EncryptionMD5Serializer
    

class EncryptionAESView(EncryptionSHA1View):
    serializer_class = EncryptionAESSerializer
    

class DecryptionAESView(EncryptionSHA1View):
    serializer_class = DecryptionAESSerializer
    
    
class EncryptionDESView(EncryptionAESView):
    serializer_class = EncryptionDESSerializer
    

class DecryptionDESView(DecryptionAESView):
    serializer_class = DecryptionDESSerializer
    
    
class EncryptionElgamalView(EncryptionSHA1View):
    serializer_class = EncryptionElgamalSerializer
    
    
class DecryptionElgamalView(EncryptionSHA1View):
    serializer_class = DecryptionElgamalSerializer
    

class EncryptionRSAView(EncryptionSHA1View):
    serializer_class = EncryptionRSASerializer
    
class DecryptionRSAView(DecryptionElgamalView):
    serializer_class = DecryptionRSASerializer
    

class EncryptionHMACMD5View(EncryptionSHA1View):
    serializer_class = EncryptionHMACMD5Serializer
   
   
class EncryptionHMACSHA1View(EncryptionSHA1View):
    serializer_class = EncryptionHMACSHA1Serializer
    
    
class EncryptionHMACSHA256View(EncryptionSHA1View):
    serializer_class = EncryptionHMACSHA256Serializer
    