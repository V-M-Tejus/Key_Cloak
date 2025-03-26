from rest_framework.authentication import BaseAuthentication

class UserServiceAuthentication(BaseAuthentication):
    def authenticate(self, request):
        return None  # Implement your logic