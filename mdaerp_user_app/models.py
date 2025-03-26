import uuid
from django.db import models
from django.utils import timezone


class UserRole(models.TextChoices):
    ADMIN = 'admin', 'Admin'
    REGULATOR = 'regulator', 'Regulator'
    MANUFACTURER = 'manufacturer', 'Manufacturer'
    COORDINATOR = 'coordinator', 'Coordinator'
    HOD = 'hod', 'HOD'
    HEALTHCARE_PROFESSIONAL = 'healthcare_professional', 'Healthcare Professional'
    PATIENT = 'patient', 'Patient'
    CONSUMER = 'consumer', 'Consumer'


class EventSeverity(models.TextChoices):
    MINOR = 'minor', 'Minor'
    MODERATE = 'moderate', 'Moderate'
    SERIOUS = 'serious', 'Serious'
    LIFE_THREATENING = 'life_threatening', 'Life Threatening'
    DEATH = 'death', 'Death'


class EventStatus(models.TextChoices):
    SUBMITTED = 'submitted', 'Submitted'
    UNDER_REVIEW = 'under_review', 'Under Review'
    INFORMATION_REQUESTED = 'information_requested', 'Information Requested'
    INVESTIGATION = 'investigation', 'Investigation'
    CLOSED = 'closed', 'Closed'
    ESCALATED = 'escalated', 'Escalated'


class DeviceCategory(models.TextChoices):
    DIAGNOSTIC = 'diagnostic', 'Diagnostic'
    THERAPEUTIC = 'therapeutic', 'Therapeutic'
    LIFE_SUPPORT = 'life_support', 'Life Support'
    SURGICAL = 'surgical', 'Surgical'
    MONITORING = 'monitoring', 'Monitoring'
    IMPLANTABLE = 'implantable', 'Implantable'
    CONSUMABLE = 'consumable', 'Consumable'
    PPE = 'ppe', 'PPE'
    OTHER = 'other', 'Other'


class Organization(models.Model):
    """Organization model for healthcare facilities, manufacturers, etc."""
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=100)
    org_type = models.CharField(max_length=50)  # hospital, manufacturer, regulatory body
    license_number = models.CharField(max_length=50, blank=True, null=True, unique=True)
    street_address = models.TextField(blank=True, null=True)
    city = models.CharField(max_length=50, blank=True, null=True)
    state = models.CharField(max_length=50, blank=True, null=True)
    country = models.CharField(max_length=50)
    postal_code = models.CharField(max_length=20, blank=True, null=True)
    contact_email = models.EmailField(max_length=120, blank=True, null=True)
    contact_phone = models.CharField(max_length=20, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'organizations'
        

class User(models.Model):
    """Extended User model with role-based access control"""
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    role = models.CharField(max_length=50, choices=UserRole.choices, default=UserRole.CONSUMER)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(max_length=120, unique=True,blank=True, null=True)
    password = models.CharField(max_length=255)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50,blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name='users')
    gender = models.CharField(max_length=20)
    phone_number = models.CharField(max_length=20)
    last_login = models.JSONField(blank=True, null=True) 
    created_at = models.DateTimeField(default=timezone.now)
    is_verified = models.BooleanField(default=False)
    profile_url = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        db_table = 'users'


class Otp(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'otps'
        

class Device(models.Model):
    """Medical device model with detailed information"""
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=100)
    brand_name = models.CharField(max_length=100, blank=True, null=True)
    model_number = models.CharField(max_length=50, blank=True, null=True)
    serial_number = models.CharField(max_length=50, blank=True, null=True, unique=True)
    batch_number = models.CharField(max_length=50, blank=True, null=True, unique=True)
    catalog_number = models.CharField(max_length=50, blank=True, null=True, unique=True )
    device_category = models.CharField(max_length=50, choices=DeviceCategory.choices)
    manufacturer = models.ForeignKey(Organization, on_delete=models.PROTECT, null=True, related_name='manufactured_devices')
    description = models.TextField(blank=True, null=True)
    intended_use = models.TextField(blank=True, null=True)
    approval_number = models.CharField(max_length=50, blank=True, null=True)
    approval_date = models.DateField(blank=True, null=True)
    is_implantable = models.BooleanField(default=False)
    is_single_use = models.BooleanField(default=False)
    faulty_components = models.CharField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)


    class Meta:
        db_table = 'devices'
        constraints = [
            models.UniqueConstraint(
                fields=['manufacturer', 'model_number', 'serial_number'],
                name='unique_device_constraint'
            )
        ]


class AdverseEvent(models.Model):
    """Main model for adverse event reporting"""
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    reference_number = models.CharField(max_length=20, unique=True)
    reporter = models.ForeignKey(User, on_delete=models.PROTECT, related_name='adverse_events')
    device = models.ForeignKey(Device, on_delete=models.PROTECT, related_name='adverse_events')
    event_date = models.DateTimeField()
    report_date = models.DateTimeField(default=timezone.now)
    event_location = models.CharField(max_length=200, blank=True, null=True)
    institution = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)
    severity = models.CharField(max_length=50, choices=EventSeverity.choices)
    description = models.TextField() 
    patient_outcome = models.TextField(blank=True, null=True)
    immediate_action = models.TextField(blank=True, null=True)
    device_usage_purpose = models.TextField(blank=True, null=True)
    device_operation_status = models.CharField(max_length=50, blank=True, null=True)
    device_available_for_evaluation = models.BooleanField(default=False)
    device_returned_to_manufacturer = models.BooleanField(default=False)
    status = models.CharField(max_length=50, choices=EventStatus.choices, default=EventStatus.SUBMITTED)
    patient_age = models.PositiveSmallIntegerField(blank=True, null=True)
    patient_gender = models.CharField(max_length=20, blank=True, null=True)
    patient_weight = models.FloatField(blank=True, null=True)
    is_public = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'adverse_events'


class EventReview(models.Model):
    """Review and assessment of reported adverse events"""
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    adverse_event = models.ForeignKey(AdverseEvent, on_delete=models.CASCADE, related_name='reviews')
    reviewer = models.ForeignKey(User, on_delete=models.PROTECT, related_name='reviews')
    review_date = models.DateTimeField(default=timezone.now)
    assessment = models.TextField()
    action_required = models.TextField(blank=True, null=True)
    risk_level = models.CharField(max_length=20, blank=True, null=True)
    conclusion = models.TextField(blank=True, null=True)
    recommendations = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'event_reviews'


class EventAttachment(models.Model):
    """Attachments for adverse event reports (images, documents, etc.)"""
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    adverse_event = models.ForeignKey(AdverseEvent, on_delete=models.CASCADE, related_name='attachments')
    file_path = models.CharField(max_length=255)
    file_type = models.CharField(max_length=50)
    description = models.TextField(blank=True, null=True)
    uploaded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'event_attachments'


class EventFollowUp(models.Model):
    """Follow-up information for adverse events"""
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    adverse_event = models.ForeignKey(AdverseEvent, on_delete=models.CASCADE, related_name='follow_ups')
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    follow_up_date = models.DateTimeField(default=timezone.now)
    description = models.TextField()

    class Meta:
        db_table = 'event_follow_ups'


class Notification(models.Model):
    """System notifications for users"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=100)
    message = models.TextField()
    external_link = models.URLField(blank=True, null=True)
    notification_type = models.CharField(max_length=50)  # alert, info, action_required
    related_event = models.ForeignKey(AdverseEvent, on_delete=models.CASCADE, blank=True, null=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'notifications'


class RegulatoryAction(models.Model):
    """Regulatory actions taken based on adverse event reports"""
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    device = models.ForeignKey(Device, on_delete=models.PROTECT)
    action_type = models.CharField(max_length=50)  # recall, field_correction, safety_alert
    action_date = models.DateTimeField()
    description = models.TextField()
    regulatory_body = models.CharField(max_length=100)
    reference_number = models.CharField(max_length=50, blank=True, null=True)
    action_status = models.CharField(max_length=50)  # initiated, in_progress, completed
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'regulatory_actions'