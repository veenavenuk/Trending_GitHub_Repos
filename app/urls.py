from django.urls import path, include
from . import views
from .views import GitHubLogin, github_callback, MyTokenObtainPairView,LoginAPIView,rest_logout
from allauth.socialaccount.providers.github import views as github_views

from .views import MyTokenObtainPairView


from rest_framework_simplejwt.views import (
    TokenRefreshView,
)


urlpatterns = [
    path('github_login/', GitHubLogin.as_view(), name='github_login'),
    path('dj-rest-auth/registration/', include('dj_rest_auth.registration.urls')),   
    path('accounts/github/login/callback/', github_callback, name='github_callback'),
    path('auth/github/url/', github_views.oauth2_login,name="account_login"),
    path('api/', views.getRoutes),
    path('token11/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('profile/logout', rest_logout, name='rest_logout'),
    
]









