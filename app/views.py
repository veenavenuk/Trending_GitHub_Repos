from django.shortcuts import render
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from django.urls import reverse

import urllib.parse
from django.shortcuts import redirect
import requests


from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import LoginSerializer
from rest_framework import generics, status, views, permissions
from rest_framework import serializers
from django.contrib.auth import get_user_model


import json
from django.http import JsonResponse

User=get_user_model()

class GitHubLogin(SocialLoginView):
    adapter_class = GitHubOAuth2Adapter
    client_class = OAuth2Client
    

def github_callback(request, *args, **kwargs):
    params = urllib.parse.urlencode(request.GET)
    params1 = request.GET
    request_data={"code":params1['code']}
    app_URL = 'http://127.0.0.1:8000/github_login/'
    response=requests.post(app_URL,request_data) 
    
    for i in User.objects.all():
        if i.access_token==None:
            obj = User.objects.last()
            obj.auth_provider='GitHub'
            obj.save()
            tokn=obj.token
   
    return render(request, "dashboard/home.html", tokn)



def rest_logout(request):
    response=requests.post('http://127.0.0.1:8000/profile/logout/')
    return render(request, "account/login.html")
    

@api_view(['GET'])
def getRoutes(request):
    routes = [
        '/api/token',
        '/api/token/refresh',
    ]

    return Response(routes)



class MyTokenObtainPairSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['username'] = user.username


        return token

    class Meta:
        model = User
        fields = ['email', 'password', 'username']

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer




        
        


    
