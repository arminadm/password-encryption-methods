from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import update_last_login
from random import randint
from django_redis import get_redis_connection


def generate_jwt_for(user):
    """
    this method gets a user object, updated the last login info and returns access and
    refresh tokens
    """
    refresh = RefreshToken.for_user(user)

    update_last_login(None, user)

    data = {"refresh": str(refresh), "access": str(refresh.access_token)}
    return data


class RedisAuthenticationService:
    def __init__(self):
        self.from_token_value = 100_000
        self.to_token_value = 999_999
        self.token_expiration = 300 # 5 * 60 seconds

    def set_phone_challenge_token(self, phone):
        # create redis connection
        redis_connection = get_redis_connection()
        redis_key_field = f'{phone}'

        # Check if the token exists
        existing_token = redis_connection.get(redis_key_field)
        
        # token has been generated for this phone number before
        if existing_token:
            token = existing_token
        else:
            # no token generated for this phone before
            token = str(randint(self.from_token_value, self.to_token_value))
        
        redis_connection.set(redis_key_field, token, ex=self.token_expiration)
    
        # DJANGO LOG
        print("##########################################")
        print(f"challenge token for {phone}: {token}")
        print("##########################################")
        
        return token

    def get_phone_challenge_token(self, phone):
        # create redis connection
        redis_connection = get_redis_connection()
        redis_key_field = f'{phone}'

        # Check if the token exists
        if existing_token := redis_connection.get(redis_key_field):
            return existing_token.decode('utf-8')
        else:
            return None
        
    def delete_phone_challenge_token(self, phone):
        # create redis connection
        redis_connection = get_redis_connection()
        redis_key_field = f'{phone}'

        # Delete the token
        result = redis_connection.delete(redis_key_field)

        # DJANGO LOG
        if result:
            print("##########################################")
            print(f"Deleted challenge token for {phone}")
            print("##########################################")
        else:
            print("##########################################")
            print(f"No token found for {phone} to delete")
            print("##########################################")
        
        return result