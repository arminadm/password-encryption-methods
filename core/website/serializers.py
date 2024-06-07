from core.settings import PASS_SALT
from rest_framework import serializers, status
from website.models import User
from website.tools.auth import generate_jwt_for
from website.tools.exception import CustomException
from website.tools.encryption import encrypt_string_sha1, encrypt_string_md5
from website.tools.auth import RedisAuthenticationService
from django.contrib.auth.password_validation import validate_password
import re
from website.tools import encryption
from Crypto.PublicKey import RSA


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
            self.initial_data["phone"]
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
            user = User.objects.get(phone=self.initial_data["phone"])
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
            
            
class EncryptionSHA1Serializer(serializers.Serializer):
    string = serializers.CharField(required=True)
    
    def encrypt(self):
        return {
            "cipher": encryption.encrypt_string_sha1(self.validated_data["string"])
        }
        

class EncryptionSHA2Serializer(EncryptionSHA1Serializer):
    def encrypt(self):
        return {
            "cipher": encryption.encrypt_string_sha2(self.validated_data["string"])
        }    
                

class EncryptionMD5Serializer(EncryptionSHA1Serializer):
    def encrypt(self):
        return {
            "cipher": encryption.encrypt_string_md5(self.validated_data["string"])
        }
        

class EncryptionAESSerializer(serializers.Serializer):
    string = serializers.CharField(required=True)
    key = serializers.CharField(required=True)

    def encrypt(self):
        iv, ct = encryption.aes_encrypt(
            data=self.validated_data["string"],
            key=self.validated_data["key"]
        )
        return {"iv": iv, "cipher": ct}


class DecryptionAESSerializer(serializers.Serializer):
    key = serializers.CharField(required=True)
    initialization_vector = serializers.CharField(required=True)
    cipher = serializers.CharField(required=True)

    def encrypt(self):
        try:
            return {
                "plain_text": encryption.aes_decrypt(
                    ct=self.validated_data["cipher"],
                    key=self.validated_data["key"],
                    iv=self.validated_data["initialization_vector"],
                )
            }
        except:
            raise CustomException(
                "مقادیر داده شده درست نمیباشد",
                "detail",
                status_code=status.HTTP_400_BAD_REQUEST
            )
            

class EncryptionDESSerializer(EncryptionAESSerializer):
    def encrypt(self):
        iv, ct = encryption.des_encrypt(
            data=self.validated_data["string"],
            key=self.validated_data["key"]
        )
        return {"iv": iv, "cipher": ct}

            
class DecryptionDESSerializer(DecryptionAESSerializer):
    def encrypt(self):
        try:
            return {
                "plain_text": encryption.des_decrypt(
                    ct=self.validated_data["cipher"],
                    key=self.validated_data["key"],
                    iv=self.validated_data["initialization_vector"],
                )
            }
        except:
            raise CustomException(
                "مقادیر داده شده درست نمیباشد",
                "detail",
                status_code=status.HTTP_400_BAD_REQUEST
            )
    

class EncryptionElgamalSerializer(EncryptionAESSerializer):
    def encrypt(self):
        private_key, public_key = encryption.generate_elgamal_keys()
        cipher = encryption.elgamal_encrypt(
            public_key=public_key, 
            data=self.validated_data["string"]
        )
        private_key = f"{private_key[0]}, {private_key[1]}, {private_key[2]}"
        public_key = f"{public_key[0]}, {public_key[1]}, {public_key[2]}"
        cipher = f"{cipher[0]}, {cipher[1]}"
        return {
            "private_key": private_key,
            "public_key": public_key,
            "cipher": cipher
        }
    

class DecryptionElgamalSerializer(serializers.Serializer):
    cipher = serializers.CharField(required=True)
    private_key = serializers.CharField(required=True)
    
    def encrypt(self):
        try:
            private_key = [int(item) for item in self.validated_data["private_key"].split(", ")]
            cipher = [int(item) for item in self.validated_data["cipher"].split(", ")]
            return {
                "plain_text": encryption.elgamal_decrypt(
                    private_key=private_key,
                    ciphertext=cipher
                )
            }
        except:
            raise CustomException(
                "مقادیر داده شده درست نمیباشد",
                "detail",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        

class EncryptionRSASerializer(EncryptionAESSerializer):
    def encrypt(self):
        private_key, public_key = encryption.generate_rsa_keys()
        cipher = encryption.rsa_encrypt(
            public_key=public_key, 
            data=self.validated_data["string"]
        )
        return {
            "private_key": private_key.export_key().decode("utf-8"),
            "public_key": public_key.export_key().decode("utf-8"),
            "cipher": str(cipher)
        }


class DecryptionRSASerializer(DecryptionElgamalSerializer):
    def encrypt(self):
        try:
            private=RSA.import_key(self.validated_data["private_key"])
            return {
                "plain_text": encryption.rsa_decrypt(
                    private_key=private,
                    ciphertext=self.validated_data["cipher"]
                )
            }
        except:
            raise CustomException(
                "مقادیر داده شده درست نمیباشد",
                "detail",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        
class EncryptionHMACMD5Serializer(serializers.Serializer):
    string = serializers.CharField(required=True)
    key = serializers.CharField(required=True)

    def encrypt(self):
        return {
            "cipher": encryption.calculate_hmac_md5(
                key=self.validated_data["key"],
                message=self.validated_data["string"]
            )
        }


class EncryptionHMACSHA1Serializer(EncryptionHMACMD5Serializer):
    def encrypt(self):
        return {
            "cipher": encryption.calculate_hmac_sha1(
                key=self.validated_data["key"],
                message=self.validated_data["string"]
            )
        }
        
        
class EncryptionHMACSHA256Serializer(EncryptionHMACMD5Serializer):
    def encrypt(self):
        return {
            "cipher":encryption.calculate_hmac_sha256(
                key=self.validated_data["key"],
                message=self.validated_data["string"]
            )
        }