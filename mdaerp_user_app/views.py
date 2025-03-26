import random
import re
from django.db import IntegrityError
from django.shortcuts import get_object_or_404
from requests import Response
from rest_framework import status
from .serializers import *
from .models import User
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.contrib.auth.hashers import make_password, check_password


from .keycloak_configuration import KeycloakConfiguration, KeycloakService

class SignInView(APIView):
    """
    View to handle user sign-in with comprehensive validation
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            username = request.data.get('username')
            password = request.data.get('password')

            # Validate input
            if not username or not password:
                return Response(
                    {"error": "Username and password are required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Find user by username
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response(
                    {"error": "Invalid credentials"}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # Verify password
            if not check_password(password, user.password):
                return Response(
                    {"error": "Invalid credentials"}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # Check if user is verified
            if not user.is_verified:
                return Response(
                    {"error": "User account is not verified"}, 
                    status=status.HTTP_403_FORBIDDEN
                )

            # Prepare user data for response
            serializer = UserSerializer(user)
            
            # Update last login 
            user.last_login = {
                'timestamp': timezone.now().isoformat(),
                'ip_address': self._get_client_ip(request)
            }
            user.save()

            return Response({
                "message": "Login successful",
                "user": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_client_ip(self, request):
        """
        Helper method to get client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SendOTPView(APIView):
    """
    View to handle OTP generation and sending during user registration
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            # Extract and validate registration data
            username = request.data.get('username')
            password = request.data.get('password')
            first_name = request.data.get('first_name')
            phone_number = request.data.get('phone_number')
            gender = request.data.get('gender')
            date_of_birth = request.data.get('date_of_birth')

            # Comprehensive input validation
            validation_errors = {}

            if not username:
                validation_errors['username'] = "Username is required"
            elif User.objects.filter(username=username).exists():
                validation_errors['username'] = "Username already exists"
            elif len(username) < 3:
                validation_errors['username'] = "Username must be at least 3 characters long"

            if not password:
                validation_errors['password'] = "Password is required"
            elif len(password) < 8:
                validation_errors['password'] = "Password must be at least 8 characters long"
            
            if not first_name:
                validation_errors['first_name'] = "First name is required"
            
            if not phone_number:
                validation_errors['phone_number'] = "Phone number is required"
            elif not re.match(r'^\+?1?\d{9,15}$', phone_number):
                validation_errors['phone_number'] = "Invalid phone number format"

            if not gender:
                validation_errors['gender'] = "Gender is required"
            
            if not date_of_birth:
                validation_errors['date_of_birth'] = "Date of birth is required"

            # If any validation errors, return them
            if validation_errors:
                return Response(
                    {"errors": validation_errors}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create new user
            hashed_password = make_password(password)
            user = User.objects.create(
                username=username,
                password=hashed_password,
                first_name=first_name,
                phone_number=phone_number,
                gender=gender,
                date_of_birth=date_of_birth
            )

            # Generate OTP
            otp_code = str(random.randint(100000, 999999))
            
            # Create OTP record
            Otp.objects.create(
                user=user,
                otp=make_password(otp_code)  # Hash OTP for security
            )

            # Here you would typically integrate with an SMS service like Twilio
            # For now, we'll just return the OTP (in production, NEVER do this!)
            return Response({
                "message": "OTP sent successfully",
                "otp": otp_code,  # REMOVE IN PRODUCTION!
                "username": username
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class VerifyOTPView(APIView):
    """
    View to verify OTP during user registration
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            username = request.data.get('username')
            otp_entered = request.data.get('otp')

            # Validate inputs
            if not username or not otp_entered:
                return Response(
                    {"error": "Username and OTP are required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Find user
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response(
                    {"error": "User not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )

            # Find latest OTP for this user
            try:
                otp_record = Otp.objects.filter(user=user).latest('created_at')
            except Otp.DoesNotExist:
                return Response(
                    {"error": "No OTP found. Please request a new OTP."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Check OTP age (valid for 10 minutes)
            otp_age = timezone.now() - otp_record.created_at
            if otp_age.total_seconds() > 600:  # 10 minutes
                return Response(
                    {"error": "OTP has expired. Please request a new one."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Verify OTP
            if check_password(otp_entered, otp_record.otp):
                # Mark user as verified
                user.is_verified = True
                user.save()

                # Optional: Delete used OTP records
                Otp.objects.filter(user=user).delete()

                # Serialize user data
                serializer = UserSerializer(user)

                return Response({
                    "message": "OTP verified successfully",
                    "user": serializer.data
                }, status=status.HTTP_200_OK)
            else:
                return Response(
                    {"error": "Invalid OTP"}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )

        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SignOutView(APIView):
    """
    View to handle user sign-out
    """
    permission_classes = [AllowAny] # Change to Authenticated KeyCloak User Condition here instead of Allow Any

    def post(self, request):
        try:
            # Invalidate the user's session or token
            user = request.user
            
            # Update last logout timestamp
            user.last_login = {
                'logout_timestamp': timezone.now().isoformat(),
                'ip_address': self._get_client_ip(request)
            }
            user.save()

            # You might want to implement token invalidation here
            # For JWT: blacklist the token
            # For session-based auth: logout the user

            return Response({
                "message": "Logged out successfully"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _get_client_ip(self, request):
        """
        Helper method to get client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SignUpView(APIView):
    """
    Comprehensive Sign Up View with Organization Association
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            # Extract user registration data
            username = request.data.get('username')
            password = request.data.get('password')
            first_name = request.data.get('first_name')
            last_name = request.data.get('last_name', '')
            email = request.data.get('email')
            phone_number = request.data.get('phone_number')
            gender = request.data.get('gender')
            date_of_birth = request.data.get('date_of_birth')
            
            # Organization-related fields
            org_name = request.data.get('organization_name')
            org_type = request.data.get('organization_type')
            org_country = request.data.get('organization_country')

            # Comprehensive validation
            validation_errors = {}

            # Username validation
            if not username:
                validation_errors['username'] = "Username is required"
            elif User.objects.filter(username=username).exists():
                validation_errors['username'] = "Username already exists"
            elif len(username) < 3:
                validation_errors['username'] = "Username must be at least 3 characters long"

            # Password validation
            if not password:
                validation_errors['password'] = "Password is required"
            elif len(password) < 8:
                validation_errors['password'] = "Password must be at least 8 characters long"

            # Required field validations
            required_fields = [
                ('first_name', first_name, "First name"),
                ('phone_number', phone_number, "Phone number"),
                ('gender', gender, "Gender"),
                ('date_of_birth', date_of_birth, "Date of birth")
            ]

            for field_name, field_value, field_label in required_fields:
                if not field_value:
                    validation_errors[field_name] = f"{field_label} is required"

            # Email validation (optional but recommended)
            if email and User.objects.filter(email=email).exists():
                validation_errors['email'] = "Email already in use"

            # Organization validation
            if not org_name or not org_type or not org_country:
                validation_errors['organization'] = "Complete organization details are required"

            # If any validation errors, return them
            if validation_errors:
                return Response({
                    "errors": validation_errors
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create Organization
            organization = Organization.objects.create(
                name=org_name,
                org_type=org_type,
                country=org_country
            )

            # Create User
            user = User.objects.create(
                username=username,
                password=make_password(password),
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone_number=phone_number,
                gender=gender,
                date_of_birth=date_of_birth,
                organization=organization,
                is_verified=False  # Will be set to True after OTP verification
            )

            # Prepare response
            serializer = UserSerializer(user)

            return Response({
                "message": "User registration initiated. Please verify OTP.",
                "user": serializer.data,
                "next_step": "verify_otp"
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class OrganizationView(APIView):
    
    def post(self, request):
        serializer = OrganizationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response({"message": "Organization created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
            
            except IntegrityError:
                return Response(
                    {"error": "Organization with this license number already exists."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, id=None):
        if id:
            organization = get_object_or_404(Organization, id=id)
            serializer = OrganizationSerializer(organization)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            organizations = Organization.objects.all()
            serializer = OrganizationSerializer(organizations, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)


class DeviceView(APIView):
    
    def post(self, request):
        serializer = DeviceSerializer(data=request.data)
        if serializer.is_valid():
            name = serializer.validated_data.get("name")
            batch_number = serializer.validated_data.get("batch_number")
            serial_number = serializer.validated_data.get("serial_number")

            existing_device = Device.objects.filter(name=name, batch_number=batch_number, serial_number=serial_number).first()

            if existing_device:
                return Response(
                    {"error": "A device with this name, batch number, and serial number already exists."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                serializer.save()
                return Response({"message": "Device created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
            except IntegrityError:
                return Response({"error": "Database integrity error occurred."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, id=None):
        if id:
            device = get_object_or_404(Device, id=id)
            serializer = DeviceSerializer(device)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            devices = Device.objects.all()
            serializer = DeviceSerializer(devices, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)


#Sample KeyCloak

class KeycloakSignUpView(APIView):
    """
    User Registration with Keycloak Integration
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            # Extract registration data
            username = request.data.get('username')
            password = request.data.get('password')
            email = request.data.get('email')
            first_name = request.data.get('first_name')
            last_name = request.data.get('last_name', '')
            
            # Validate required fields
            if not all([username, password, email, first_name]):
                return Response({
                    "error": "Missing required fields"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if username exists
            if User.objects.filter(username=username).exists():
                return Response({
                    "error": "Username already exists"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create Organization (if applicable)
            organization = Organization.objects.create(
                name=request.data.get('organization_name', 'Default Org'),
                org_type=request.data.get('organization_type', 'Default'),
                country=request.data.get('organization_country', 'Default')
            )

            # Create Django User
            user = User.objects.create(
                username=username,
                email=email,
                password=make_password(password),
                first_name=first_name,
                last_name=last_name,
                organization=organization,
                is_verified=False
            )

            # Create Keycloak User
            keycloak_service = KeycloakService()
            keycloak_user_created = keycloak_service.create_keycloak_user({
                'username': username,
                'password': password,
                'email': email,
                'first_name': first_name,
                'last_name': last_name
            })

            if not keycloak_user_created:
                # Rollback user creation if Keycloak fails
                user.delete()
                organization.delete()
                return Response({
                    "error": "Failed to create Keycloak user"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Prepare response
            serializer = UserSerializer(user)
            return Response({
                "message": "User registered successfully",
                "user": serializer.data
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class KeycloakSignInView(APIView):
    """
    User Login with Keycloak Token Generation
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            username = request.data.get('username')
            password = request.data.get('password')

            # Validate input
            if not username or not password:
                return Response({
                    "error": "Username and password are required"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Verify user exists
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response({
                    "error": "Invalid credentials"
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Authenticate via Keycloak
            keycloak_service = KeycloakService()
            tokens = keycloak_service.authenticate_user(username, password)

            if not tokens:
                return Response({
                    "error": "Authentication failed"
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Update last login
            user.last_login = timezone.now()
            user.save()

            # Prepare response
            serializer = UserSerializer(user)
            return Response({
                "message": "Login successful",
                "user": serializer.data,
                "tokens": tokens
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class KeycloakLogoutView(APIView):
    """
    User Logout with Keycloak Token Invalidation
    """
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')

            if not refresh_token:
                return Response({
                    "error": "Refresh token is required"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Logout via Keycloak
            keycloak_service = KeycloakService()
            logout_success = keycloak_service.logout(refresh_token)

            if logout_success:
                return Response({
                    "message": "Logout successful"
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": "Logout failed"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        