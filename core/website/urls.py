from django.urls import path
from .views import (
   SignupView, LoginStep1View, LoginStep2View,
   EncryptionSHA1View, EncryptionSHA2View, EncryptionMD5View,
   EncryptionAESView, DecryptionAESView, EncryptionDESView,
   DecryptionDESView, EncryptionElgamalView, DecryptionElgamalView,
   EncryptionRSAView, DecryptionRSAView,
   EncryptionHMACMD5View, EncryptionHMACSHA1View, EncryptionHMACSHA256View
)


urlpatterns = [
   path("signup/", SignupView.as_view(), name="signup"),
   path("login/step1/", LoginStep1View.as_view(), name="login-step1"),
   path("login/step2/", LoginStep2View.as_view(), name="login-step2"),
   
   path("sha1/encryption/", EncryptionSHA1View.as_view(), name="encryption-sha1"),
   path("sha2/encryption/", EncryptionSHA2View.as_view(), name="encryption-sha2"),
   path("md5/encryption/", EncryptionMD5View.as_view(), name="encryption-md5"),
   
   path("aes/encryption/", EncryptionAESView.as_view(), name="encryption-aes"),
   path("aes/decryption/", DecryptionAESView.as_view(), name="decryption-aes"),
   
   path("des/encryption/", EncryptionDESView.as_view(), name="encryption-des"),
   path("des/decryption/", DecryptionDESView.as_view(), name="decryption-des"),
   
   path("elgamal/encryption/", EncryptionElgamalView.as_view(), name="encryption-elgamal"),
   path("elgamal/decryption/", DecryptionElgamalView.as_view(), name="decryption-elgamal"),
   
   path("rsa/encryption/", EncryptionRSAView.as_view(), name="encryption-rsa"),
   path("rsa/decryption/", DecryptionRSAView.as_view(), name="decryption-rsa"),
   
   path("hmac/md5/encryption/", EncryptionHMACMD5View.as_view(), name="encryption-hmac-md5"),
   path("hmac/sha1/encryption/", EncryptionHMACSHA1View.as_view(), name="encryption-hmac-sha1"),
   path("hmac/sha256/encryption/", EncryptionHMACSHA256View.as_view(), name="encryption-hmac-sha256"),
]
