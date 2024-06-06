from core.settings import PASS_SALT
from rest_framework import serializers, status
from website.models import User
from website.tools.auth import generate_jwt_for
from website.tools.exception import CustomException
from website.tools.encryption import encrypt_string_sha1, encrypt_string_md5
from website.tools.auth import RedisAuthenticationService
from django.contrib.auth.password_validation import validate_password
import re


class SignupSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(required=True)
    class Meta:
        model = User
        fields = ["phone", "password", "password2"]
        
    def validate(self, attrs):
        if attrs["password2"] != attrs["password"]:
            raise CustomException(
                "مقادیر دو پسورد یکسان نیست",
                "detail",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # validate phone number
        pattern = r"^9\d{9}$"
        if not re.match(pattern, str(attrs["phone"])):
            raise CustomException(
                "فرمت شماره وارد شده قابل قبول نمیباشد",
                "detail",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # validate the password
        try:
            validate_password(attrs["password"])
        except Exception as e:
            # normalize the errors
            error = ""
            for err in e:
                error += err + " "
            
            # raise errors
            raise CustomException(
                f"password is not valid: {error}",
                "detail",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        
        attrs.pop("password2")
            
        return super().validate(attrs)
    
    def create(self, validated_data):
        # hash the password using salt
        encrypt_pass = encrypt_string_sha1(
            validated_data["password"] + PASS_SALT
        )
        
        return User.objects.create(
            phone=validated_data["phone"],
            sha1_password=encrypt_pass,
        )


class LoginStep1Serializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["phone"]


    def get_challenge(self):
        # check if the given phone already exists
        phone = self.initial_data["phone"]
        if not User.objects.filter(phone=phone).exists():
            raise CustomException(
                "این شماره قبلا ثبت نام نشده است",
                "detail",
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        redis = RedisAuthenticationService()
        challenge_token = redis.set_phone_challenge_token(
            phone=phone
        )
        return challenge_token
    
    
class LoginStep2Serializer(serializers.Serializer):
    hash_pass = serializers.CharField(required=True)
    phone = serializers.IntegerField(required=True)
    
    def validate(self, attrs):
        validated_data = super().validate(attrs)
        
        # check challenge token
        redis = RedisAuthenticationService()
        if challenge_token := redis.get_phone_challenge_token(
            self.validated_data["phone"]
        ):
            self.challenge_token = challenge_token
        else:
            raise CustomException(
                "توکنی با اطلاعات داده شده یافت نشد",
                "detail",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # get user instance by phone number
        try:
            user = User.objects.get(phone=self.validated_data["phone"])
        except User.DoesNotExist:
            raise CustomException(
                "کاربری با شماره داده شده یافت نشد",
                "detail",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            raise CustomException(
                f"unknown error happened: {e}",
                "detail",
                status_code=status.HTTP_501_NOT_IMPLEMENTED
            )
        self.user = user
        
        return validated_data
            
    def check_credentials(self):
        # generate hash_pass in server-side
        server_side_hash_pass = encrypt_string_md5(
            self.user.sha1_password + self.challenge_token
        )
        client_side_hash_pass = self.validated_data["hash_pass"]
        
        # DJANGO LOG
        print("###########################################")
        print(f"client side hashed password: {client_side_hash_pass}")
        print("###########################################")
        print(f"server side hashed password: {server_side_hash_pass}")
        print("###########################################")
        
        
        if server_side_hash_pass == client_side_hash_pass:
            # clear redis challenge token
            redis = RedisAuthenticationService()
            redis.delete_phone_challenge_token(self.validated_data["phone"])
            
            # return jwt 
            data = generate_jwt_for(self.user)
            return data
        
        else:
            # password incorrect
            raise CustomException(
                "رمز داده شده صحیح نمیباشد",
                "detail",
                status_code=status.HTTP_400_BAD_REQUEST
            )