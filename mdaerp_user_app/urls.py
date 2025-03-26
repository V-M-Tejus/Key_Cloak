from django.urls import path
from .views import *

URL_PATTERNS = [
    path('signin', SignInView.as_view(), name='signin'),
    path('signout', SignOutView.as_view(), name='signout'),
    path('signup', SignUpView.as_view(), name='signup'),
    path('verify-otp', VerifyOTPView.as_view(), name='verify-otp'),
    path('send-otp', SendOTPView.as_view(), name='send-otp'),
    # path('update-profile', UpdateProfileView.as_view(), name='update-profile'),
    path('devices/create/', DeviceView.as_view()),
    path('devices/<int:id>/', DeviceView.as_view()),
    path('devices/', DeviceView.as_view()),
    path('organizations/create/', OrganizationView.as_view()),
    path('organizations/<int:id>/', OrganizationView.as_view()),
    path('organizations/', OrganizationView.as_view()),

    #KeyCloak URls

    path('KCsignup/', KeycloakSignUpView.as_view(), name='keycloak-signup'),
    path('KCsignin/', KeycloakSignInView.as_view(), name='keycloak-signin'),
    path('KClogout/', KeycloakLogoutView.as_view(), name='keycloak-logout'),
    ]