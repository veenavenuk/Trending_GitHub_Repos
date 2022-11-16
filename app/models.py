from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin)

from rest_framework_simplejwt.tokens import RefreshToken

import jwt
from datetime import datetime, timedelta
from django.conf import settings




class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None, **extra_fields):
        if username is None:
            raise TypeError('Users should have a username')
        if email is None:
            raise TypeError('Users should have a Email')

        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_verified', True)

        user = self.model(username=username, email=self.normalize_email(email))
        user.is_active = True
        user.is_verified = True
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        if password is None:
            raise TypeError('Password should not be none')

        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user

       


AUTH_PROVIDERS = {'facebook': 'facebook', 'google': 'google',
                  'GitHub': 'GitHub', 'email': 'email'}


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    is_verified = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    auth_provider = models.CharField(
        max_length=255, blank=False,
        null=False, default=AUTH_PROVIDERS.get('email'))
    
    access_token=models.CharField(max_length=255, blank=True, null=True)
    refresh_token=models.CharField(max_length=255, blank=True, null=True)
    

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    objects = UserManager()

    def __str__(self):
        return self.email


    @property
    def token(self):
        return self._generate_jwt_token()

    def get_full_name(self):
        return self.username

    def get_short_name(self): 
        return self.username

    def _generate_jwt_token(self):
        # dt = datetime.now() + timedelta(days=60)

        # token = jwt.encode({
        #     'email' : self.email,
        #     'password':self.password,
        #     'id': self.pk,
        #     'exp': int(dt.strftime('%s'))
        # }, settings.SECRET_KEY, algorithm='HS256')
        # tkn = token.encode('utf-8')
        # return tkn.decode('utf-8')


        refresh = RefreshToken.for_user(self)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }





