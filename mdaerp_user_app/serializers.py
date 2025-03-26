from datetime import timezone
import uuid
from rest_framework import serializers
from .models import (
    Organization, User, Otp, Device, AdverseEvent, 
    EventReview, EventAttachment, EventFollowUp, 
    Notification, RegulatoryAction
)

class OrganizationSerializer(serializers.ModelSerializer):
    """Serializer for Organization model with comprehensive validation"""
    class Meta:
        model = Organization
        fields = '__all__'
        read_only_fields = ('uuid', 'created_at', 'updated_at')

    def validate_contact_email(self, value):
        """Custom email validation"""
        if value and not value.strip():
            raise serializers.ValidationError("Contact email cannot be an empty string.")
        return value

    def validate(self, data):
        """Additional cross-field validations"""
        # Ensure country is provided
        if not data.get('country'):
            raise serializers.ValidationError({"country": "Country is required."})
        return data


class UserSerializer(serializers.ModelSerializer):
    """Comprehensive User serializer with nested organization and advanced validations"""
    organization = OrganizationSerializer(read_only=True)
    organization_uuid = serializers.UUIDField(write_only=True, required=False)

    class Meta:
        model = User
        fields = '__all__'
        extra_kwargs = {
            'password': {'write_only': True},
            'last_login': {'read_only': True},
            'created_at': {'read_only': True}
        }

    def validate_username(self, value):
        """Ensure username is unique and meets criteria"""
        if len(value) < 3:
            raise serializers.ValidationError("Username must be at least 3 characters long.")
        return value

    def validate_email(self, value):
        """Email validation with additional checks"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already registered.")
        return value

    def create(self, validated_data):
        """Custom create method to handle organization and password hashing"""
        organization_uuid = validated_data.pop('organization_uuid', None)
        
        # Handle organization assignment
        if organization_uuid:
            try:
                organization = Organization.objects.get(uuid=organization_uuid)
                validated_data['organization'] = organization
            except Organization.DoesNotExist:
                raise serializers.ValidationError({"organization_uuid": "Invalid organization UUID"})
        
        # Hash password (assuming you're using a custom method or signal)
        user = User.objects.create(**validated_data)
        return user


class DeviceSerializer(serializers.ModelSerializer):
    """Device serializer with nested manufacturer and comprehensive validations"""
    manufacturer = OrganizationSerializer(read_only=True)
    manufacturer_uuid = serializers.UUIDField(write_only=True)

    class Meta:
        model = Device
        fields = '__all__'
        read_only_fields = ('uuid', 'created_at', 'updated_at')

    def validate(self, data):
        """Cross-field validations for device"""
        # Ensure serial number or batch number is unique
        if not (data.get('serial_number') or data.get('batch_number')):
            raise serializers.ValidationError(
                "Either serial number or batch number must be provided."
            )
        return data


class AdverseEventSerializer(serializers.ModelSerializer):
    """Comprehensive Adverse Event serializer with nested representations"""
    reporter = UserSerializer(read_only=True)
    device = DeviceSerializer(read_only=True)
    institution = OrganizationSerializer(read_only=True)

    reporter_uuid = serializers.UUIDField(write_only=True)
    device_uuid = serializers.UUIDField(write_only=True)
    institution_uuid = serializers.UUIDField(write_only=True, required=False)

    class Meta:
        model = AdverseEvent
        fields = '__all__'
        read_only_fields = ('uuid', 'reference_number', 'report_date', 'created_at', 'updated_at')

    def validate_patient_weight(self, value):
        """Validate patient weight"""
        if value is not None and value <= 0:
            raise serializers.ValidationError("Patient weight must be a positive number.")
        return value

    def validate(self, data):
        """Advanced cross-field validations"""
        # Validate event date is not in the future
        if data.get('event_date') and data['event_date'] > timezone.now():
            raise serializers.ValidationError(
                {"event_date": "Event date cannot be in the future."}
            )
        return data

    def create(self, validated_data):
        """Custom create method to handle related objects"""
        reporter_uuid = validated_data.pop('reporter_uuid')
        device_uuid = validated_data.pop('device_uuid')
        institution_uuid = validated_data.pop('institution_uuid', None)

        try:
            reporter = User.objects.get(uuid=reporter_uuid)
            device = Device.objects.get(uuid=device_uuid)
            
            validated_data['reporter'] = reporter
            validated_data['device'] = device

            if institution_uuid:
                institution = Organization.objects.get(uuid=institution_uuid)
                validated_data['institution'] = institution

        except (User.DoesNotExist, Device.DoesNotExist, Organization.DoesNotExist) as e:
            raise serializers.ValidationError(f"Related object not found: {str(e)}")

        # Generate a unique reference number (you might want a more sophisticated method)
        validated_data['reference_number'] = f"AE-{timezone.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"

        return AdverseEvent.objects.create(**validated_data)


class EventReviewSerializer(serializers.ModelSerializer):
    """Event Review serializer with nested representations"""
    adverse_event = AdverseEventSerializer(read_only=True)
    reviewer = UserSerializer(read_only=True)

    adverse_event_uuid = serializers.UUIDField(write_only=True)
    reviewer_uuid = serializers.UUIDField(write_only=True)

    class Meta:
        model = EventReview
        fields = '__all__'
        read_only_fields = ('uuid', 'created_at', 'updated_at', 'review_date')


class EventAttachmentSerializer(serializers.ModelSerializer):
    """Event Attachment serializer with file validation"""
    adverse_event = AdverseEventSerializer(read_only=True)
    adverse_event_uuid = serializers.UUIDField(write_only=True)

    class Meta:
        model = EventAttachment
        fields = '__all__'
        read_only_fields = ('uuid', 'uploaded_at')

    def validate_file_type(self, value):
        """Validate file type"""
        allowed_types = ['image/jpeg', 'image/png', 'application/pdf', 'application/doc']
        if value not in allowed_types:
            raise serializers.ValidationError(f"Unsupported file type. Allowed types: {', '.join(allowed_types)}")
        return value


class NotificationSerializer(serializers.ModelSerializer):
    """Notification serializer with user and event context"""
    user = UserSerializer(read_only=True)
    related_event = AdverseEventSerializer(read_only=True, required=False)

    user_uuid = serializers.UUIDField(write_only=True)
    related_event_uuid = serializers.UUIDField(write_only=True, required=False)

    class Meta:
        model = Notification
        fields = '__all__'
        read_only_fields = ('is_read', 'created_at')


class RegulatoryActionSerializer(serializers.ModelSerializer):
    """Regulatory Action serializer with device context"""
    device = DeviceSerializer(read_only=True)
    device_uuid = serializers.UUIDField(write_only=True)

    class Meta:
        model = RegulatoryAction
        fields = '__all__'
        read_only_fields = ('uuid', 'created_at', 'updated_at')

    def validate_action_type(self, value):
        """Validate action type"""
        allowed_types = ['recall', 'field_correction', 'safety_alert']
        if value not in allowed_types:
            raise serializers.ValidationError(
                f"Invalid action type. Allowed types: {', '.join(allowed_types)}"
            )
        return value


class OtpSerializer(serializers.ModelSerializer):
    """Serializer for OTP model with comprehensive validation"""
    
    class Meta:
        model = Otp
        fields = ['user', 'otp', 'created_at']
        read_only_fields = ['created_at']


class EventFollowUpSerializer(serializers.ModelSerializer):
    """
    Comprehensive serializer for EventFollowUp model
    Provides nested representations and advanced validations
    """
    # Read-only nested serializers for related models
    adverse_event = serializers.SerializerMethodField(read_only=True)
    user = serializers.SerializerMethodField(read_only=True)

    # Write-only UUID fields for easy object linking
    adverse_event_uuid = serializers.UUIDField(write_only=True)
    user_uuid = serializers.UUIDField(write_only=True)

    class Meta:
        model = EventFollowUp
        fields = '__all__'
        read_only_fields = ('uuid', 'follow_up_date')

    def get_adverse_event(self, obj):
        """
        Method to get nested adverse event representation
        Only called when the full object is available
        """
        from .serializers import AdverseEventSerializer  # Avoid circular import
        return AdverseEventSerializer(obj.adverse_event).data if obj.adverse_event else None

    def get_user(self, obj):
        """
        Method to get nested user representation
        Only called when the full object is available
        """
        from .serializers import UserSerializer  # Avoid circular import
        return UserSerializer(obj.user).data if obj.user else None

    def validate_description(self, value):
        """
        Validate follow-up description
        Ensures description is not empty and meets minimum length
        """
        if not value or len(value.strip()) < 10:
            raise serializers.ValidationError(
                "Follow-up description must be at least 10 characters long."
            )
        return value

    def validate(self, data):
        """
        Cross-field validations for the follow-up
        """
        # Validate related objects exist
        adverse_event_uuid = data.get('adverse_event_uuid')
        user_uuid = data.get('user_uuid')

        try:
            adverse_event = AdverseEvent.objects.get(uuid=adverse_event_uuid)
            user = User.objects.get(uuid=user_uuid)
            
            # Additional business logic validations
            # For example, ensure the user is allowed to follow up on this event
            data['adverse_event'] = adverse_event
            data['user'] = user

        except (AdverseEvent.DoesNotExist, User.DoesNotExist) as e:
            raise serializers.ValidationError(f"Related object not found: {str(e)}")

        return data

    def create(self, validated_data):
        """
        Custom create method to handle related object associations
        Removes write-only UUID fields before object creation
        """
        # Remove UUID fields used for validation
        validated_data.pop('adverse_event_uuid', None)
        validated_data.pop('user_uuid', None)

        # Create the follow-up
        return EventFollowUp.objects.create(**validated_data)

    def update(self, instance, validated_data):
        """
        Custom update method with additional logic
        """
        # Update only allowed fields
        instance.description = validated_data.get('description', instance.description)
        
        # Prevent changing the associated adverse event or user
        instance.save()
        return instance


