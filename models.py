from flask_login import UserMixin
from datetime import datetime
import re

# Import db from extensions to avoid circular imports
from extensions import db

def validate_imei(imei):
    """Validate IMEI number - must be exactly 15 digits"""
    if not imei:
        return False
    # Remove any spaces or special characters
    cleaned_imei = re.sub(r'[^0-9]', '', str(imei))
    return len(cleaned_imei) == 15 and cleaned_imei.isdigit()

def validate_serial_number(serial):
    """Validate serial number - must be exactly 15 characters"""
    if not serial:
        return False
    # Remove whitespace
    cleaned_serial = str(serial).strip()
    return len(cleaned_serial) == 15

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20))
    role = db.Column(db.String(50), nullable=False)  # super_admin, state_admin, algon_focal, dcr_focal
    organization = db.Column(db.String(100))  # ALGON, NPC, etc.
    state_id = db.Column(db.Integer, db.ForeignKey('states.id'))
    lga_id = db.Column(db.Integer, db.ForeignKey('lgas.id'))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    signature_data = db.Column(db.Text)  # Base64 encoded signature
    
    # Relationships
    state = db.relationship('State', backref='users')
    lga = db.relationship('LGA', backref='users')

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'full_name': self.full_name,
            'phone': self.phone,
            'role': self.role,
            'organization': self.organization,
            'state_id': self.state_id,
            'state_name': self.state.name if self.state else None,
            'lga_id': self.lga_id,
            'lga_name': self.lga.name if self.lga else None,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            # For focal person specific data
            'name': self.full_name,
            'role_type': self.role.replace('_focal', '').upper() if '_focal' in self.role else None
        }

class State(db.Model):
    __tablename__ = 'states'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    code = db.Column(db.String(10), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    lgas = db.relationship('LGA', backref='state', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'code': self.code
        }

class LGA(db.Model):
    __tablename__ = 'lgas'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(10), nullable=False)
    state_id = db.Column(db.Integer, db.ForeignKey('states.id'), nullable=False)
    chairman_name = db.Column(db.String(200))
    chairman_phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    wards = db.relationship('Ward', backref='lga', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'code': self.code,
            'state_id': self.state_id,
            'state_name': self.state.name if self.state else None,
            'chairman_name': self.chairman_name,
            'chairman_phone': self.chairman_phone
        }

class Ward(db.Model):
    __tablename__ = 'wards'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(10))
    lga_id = db.Column(db.Integer, db.ForeignKey('lgas.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ward officer basic information
    ward_officer_name = db.Column(db.String(200))
    ward_officer_phone = db.Column(db.String(20))
    ward_officer_email = db.Column(db.String(120))
    ward_officer_staff_id = db.Column(db.String(50))
    ward_officer_designation = db.Column(db.String(100))  # Role like "Health Worker", "Registrar"
    
    # Ward officer banking and identification information
    ward_officer_nin = db.Column(db.String(11))  # National Identification Number
    ward_officer_bank_name = db.Column(db.String(100))  # Optional
    ward_officer_account_number = db.Column(db.String(20))  # Optional
    
    # Registration center information
    registration_center_name = db.Column(db.String(200))
    registration_center_address = db.Column(db.Text)
    
    # Device assignment information (when ward officer receives device)
    device_serial_number = db.Column(db.String(100))
    device_imei1 = db.Column(db.String(20))
    device_imei2 = db.Column(db.String(20))
    device_issued_date = db.Column(db.DateTime)
    device_condition = db.Column(db.String(20))  # New, Good, Fair
    device_condition_notes = db.Column(db.Text)
    issued_by_focal_person_id = db.Column(db.Integer, db.ForeignKey('focal_persons.id'))
    
    # Relationships
    issued_by_focal_person = db.relationship('FocalPerson', backref='device_issued_to_wards')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'code': self.code,
            'lga_id': self.lga_id,
            'lga_name': self.lga.name if self.lga else None,
            'ward_officer_name': self.ward_officer_name,
            'ward_officer_phone': self.ward_officer_phone,
            'ward_officer_email': self.ward_officer_email,
            'ward_officer_staff_id': self.ward_officer_staff_id,
            'ward_officer_designation': self.ward_officer_designation,
            'ward_officer_nin': self.ward_officer_nin,
            'ward_officer_bank_name': self.ward_officer_bank_name,
            'ward_officer_account_number': self.ward_officer_account_number,
            'registration_center_name': self.registration_center_name,
            'registration_center_address': self.registration_center_address,
            'device_serial_number': self.device_serial_number,
            'device_imei1': self.device_imei1,
            'device_imei2': self.device_imei2,
            'device_issued_date': self.device_issued_date.isoformat() if self.device_issued_date else None,
            'device_condition': self.device_condition,
            'device_condition_notes': self.device_condition_notes,
            'issued_by_focal_person_id': self.issued_by_focal_person_id,
            'issued_by_focal_person_name': self.issued_by_focal_person.name if self.issued_by_focal_person else None
        }

class Device(db.Model):
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    device_type = db.Column(db.String(50), nullable=False, default='VERXID Tablet')
    model = db.Column(db.String(100))
    manufacturer = db.Column(db.String(100), default='VERXID')
    imei1 = db.Column(db.String(20), nullable=False)
    imei2 = db.Column(db.String(20))
    barcode = db.Column(db.String(100))
    carton_number = db.Column(db.String(50))
    
    # Status tracking
    status = db.Column(db.String(20), default='unclaimed')  # unclaimed, claimed, distributed
    condition = db.Column(db.String(20), default='New')  # New, Good, Fair
    condition_notes = db.Column(db.Text)
    
    # Assignment information
    state_id = db.Column(db.Integer, db.ForeignKey('states.id'))
    lga_id = db.Column(db.Integer, db.ForeignKey('lgas.id'))
    assigned_focal_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    claimed_at = db.Column(db.DateTime)
    distributed_at = db.Column(db.DateTime)
    
    # Relationships
    state = db.relationship('State', backref='devices')
    lga = db.relationship('LGA', backref='devices')
    assigned_focal = db.relationship('User', backref='assigned_devices', foreign_keys=[assigned_focal_id])
    
    def to_dict(self):
        return {
            'id': self.id,
            'serial_number': self.serial_number,
            'device_type': self.device_type,
            'model': self.model,
            'manufacturer': self.manufacturer,
            'imei1': self.imei1,
            'imei2': self.imei2,
            'barcode': self.barcode,
            'status': self.status,
            'condition': self.condition,
            'state_id': self.state_id,
            'state_name': self.state.name if self.state else None,
            'lga_id': self.lga_id,
            'lga_name': self.lga.name if self.lga else None,
            'assigned_focal_id': self.assigned_focal_id,
            'assigned_focal_name': self.assigned_focal.full_name if self.assigned_focal else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'claimed_at': self.claimed_at.isoformat() if self.claimed_at else None,
            'distributed_at': self.distributed_at.isoformat() if self.distributed_at else None
        }
    
    def validate_device_data(self):
        """Validate device data before saving"""
        errors = []
        
        # Validate serial number
        if not validate_serial_number(self.serial_number):
            errors.append("Serial number must be exactly 15 characters")
        
        # Check for duplicate serial number
        existing_device = Device.query.filter_by(serial_number=self.serial_number).first()
        if existing_device and existing_device.id != self.id:
            errors.append(f"Serial number '{self.serial_number}' already exists")
        
        # Validate IMEI1 (required)
        if not validate_imei(self.imei1):
            errors.append("IMEI1 must be exactly 15 digits")
        else:
            # Check for duplicate IMEI1
            existing_imei1 = Device.query.filter_by(imei1=self.imei1).first()
            if existing_imei1 and existing_imei1.id != self.id:
                errors.append(f"IMEI1 '{self.imei1}' already exists")
        
        # Validate IMEI2 (optional but must be valid if provided)
        if self.imei2 and not validate_imei(self.imei2):
            errors.append("IMEI2 must be exactly 15 digits if provided")
        elif self.imei2:
            # Check for duplicate IMEI2
            existing_imei2 = Device.query.filter_by(imei2=self.imei2).first()
            if existing_imei2 and existing_imei2.id != self.id:
                errors.append(f"IMEI2 '{self.imei2}' already exists")
        
        # Check if IMEI1 and IMEI2 are the same
        if self.imei2 and self.imei1 == self.imei2:
            errors.append("IMEI1 and IMEI2 cannot be the same")
        
        return errors
    
    @staticmethod
    def create_validated_device(**kwargs):
        """Create a new device with validation"""
        device = Device(**kwargs)
        errors = device.validate_device_data()
        if errors:
            return None, errors
        return device, []

class DeviceClaim(db.Model):
    __tablename__ = 'device_claims'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    claimer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    witness_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Claim details
    claim_date = db.Column(db.DateTime, default=datetime.utcnow)
    testing_completed = db.Column(db.Boolean, default=False)
    verification_completed = db.Column(db.Boolean, default=False)
    
    # Signatures
    claimer_signature = db.Column(db.Text)
    witness_signature = db.Column(db.Text)
    
    # Status
    status = db.Column(db.String(20), default='pending')  # pending, witnessed, completed
    
    # Relationships
    device = db.relationship('Device', backref='claims')
    claimer = db.relationship('User', foreign_keys=[claimer_id], backref='device_claims')
    witness = db.relationship('User', foreign_keys=[witness_id], backref='witnessed_claims')

class VerxidIssuanceForm(db.Model):
    __tablename__ = 'verxid_issuance_forms'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    issuer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Section A: Device Information
    device_type = db.Column(db.String(100))
    make_model = db.Column(db.String(100))
    serial_number = db.Column(db.String(100))
    
    # Accessories (quantities)
    charger_qty = db.Column(db.Integer, default=0)
    power_cable_qty = db.Column(db.Integer, default=0)
    sim_card_qty = db.Column(db.Integer, default=0)
    protective_case_qty = db.Column(db.Integer, default=0)
    stylus_pen_qty = db.Column(db.Integer, default=0)
    user_manual_qty = db.Column(db.Integer, default=0)
    other_accessories = db.Column(db.String(500))
    
    # Device condition
    device_condition = db.Column(db.String(20), default='New')
    condition_notes = db.Column(db.Text)
    
    # Section B: Recipient Information
    recipient_name = db.Column(db.String(200), nullable=False)
    recipient_designation = db.Column(db.String(100))
    recipient_staff_id = db.Column(db.String(50))
    registration_center = db.Column(db.String(200))
    recipient_phone = db.Column(db.String(20))
    recipient_email = db.Column(db.String(120))
    recipient_lga = db.Column(db.String(100))
    recipient_state = db.Column(db.String(100))
    
    # Section C: Issuing Authority (auto-populated from issuer)
    issuer_name = db.Column(db.String(200))
    issuer_title = db.Column(db.String(100))
    issuing_office = db.Column(db.String(200))
    issuance_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Section D: Terms Acceptance
    terms_accepted = db.Column(db.Boolean, default=False)
    
    # Section E: Digital Signatures
    recipient_signature = db.Column(db.Text)
    recipient_signature_date = db.Column(db.DateTime)
    recipient_printed_name = db.Column(db.String(200))
    
    issuer_signature = db.Column(db.Text)
    issuer_signature_date = db.Column(db.DateTime)
    issuer_printed_name = db.Column(db.String(200))
    
    witness_signature = db.Column(db.Text)
    witness_signature_date = db.Column(db.DateTime)
    witness_printed_name = db.Column(db.String(200))
    witness_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # System fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='draft')  # draft, completed
    
    # Relationships
    device = db.relationship('Device', backref='issuance_forms')
    issuer = db.relationship('User', foreign_keys=[issuer_id], backref='issued_forms')
    witness = db.relationship('User', foreign_keys=[witness_id], backref='witnessed_forms')

class Distribution(db.Model):
    __tablename__ = 'distributions'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    distributor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipient_name = db.Column(db.String(200), nullable=False)
    recipient_designation = db.Column(db.String(100))
    recipient_phone = db.Column(db.String(20))
    ward_id = db.Column(db.Integer, db.ForeignKey('wards.id'))
    
    distribution_date = db.Column(db.DateTime, default=datetime.utcnow)
    witness_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Signatures
    distributor_signature = db.Column(db.Text)
    recipient_signature = db.Column(db.Text)
    witness_signature = db.Column(db.Text)
    
    # Status
    status = db.Column(db.String(20), default='completed')
    
    # Relationships
    device = db.relationship('Device', backref='distributions')
    distributor = db.relationship('User', foreign_keys=[distributor_id], backref='distributions')
    recipient_ward = db.relationship('Ward', backref='distributions')
    witness = db.relationship('User', foreign_keys=[witness_id], backref='distribution_witnesses')


class BulkImeiUpload(db.Model):
    __tablename__ = 'bulk_imei_uploads'
    
    id = db.Column(db.Integer, primary_key=True)
    upload_session = db.Column(db.String(100), nullable=False)
    imei1 = db.Column(db.String(20), nullable=False)
    imei2 = db.Column(db.String(20))
    barcode_data = db.Column(db.String(500))
    state_code = db.Column(db.String(10))
    lga_code = db.Column(db.String(10))
    processing_status = db.Column(db.String(20), default='pending')  # pending, processed, error
    error_message = db.Column(db.Text)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    uploader = db.relationship('User', backref='bulk_uploads')

class FocalPerson(db.Model):
    __tablename__ = 'focal_persons'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120))
    lga_id = db.Column(db.Integer, db.ForeignKey('lgas.id'), nullable=False)
    role_type = db.Column(db.String(20), nullable=False)  # ALGON, DCR
    organization = db.Column(db.String(50))
    witness_for_id = db.Column(db.Integer, db.ForeignKey('focal_persons.id'))  # For DCR witnessing ALGON
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Banking and identification information
    nin = db.Column(db.String(11))  # National Identification Number
    bank_name = db.Column(db.String(100))  # Optional
    account_number = db.Column(db.String(20))  # Optional
    
    # User account link (if they have login access)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    lga = db.relationship('LGA', backref='focal_persons')
    witness_for = db.relationship('FocalPerson', remote_side=[id], backref='witnesses')
    user_account = db.relationship('User', backref='focal_person_record')

class CSVUploadLog(db.Model):
    __tablename__ = 'csv_upload_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    upload_type = db.Column(db.String(50), nullable=False)  # devices, focals, states, lgas
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    total_records = db.Column(db.Integer, default=0)
    successful_records = db.Column(db.Integer, default=0)
    failed_records = db.Column(db.Integer, default=0)
    error_details = db.Column(db.Text)
    status = db.Column(db.String(20), default='completed')  # processing, completed, failed
    
    uploader = db.relationship('User', backref='csv_uploads')

class SystemLogo(db.Model):
    __tablename__ = 'system_logos'
    
    id = db.Column(db.Integer, primary_key=True)
    organization = db.Column(db.String(50), nullable=False, unique=True)  # NPC, ALGON, UNICEF
    logo_filename = db.Column(db.String(200), nullable=False)
    logo_data = db.Column(db.LargeBinary)  # Store logo as binary data
    content_type = db.Column(db.String(100))  # image/png, image/jpeg, etc.
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    uploader = db.relationship('User', backref='uploaded_logos')
    
    def to_dict(self):
        return {
            'id': self.id,
            'organization': self.organization,
            'logo_filename': self.logo_filename,
            'content_type': self.content_type,
            'uploaded_by': self.uploaded_by,
            'upload_date': self.upload_date.isoformat() if self.upload_date else None,
            'is_active': self.is_active
        }