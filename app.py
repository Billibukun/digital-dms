from flask import Flask
from werkzeug.security import generate_password_hash
import os

# Import extensions first
from extensions import db, login_manager

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'verxid-device-management-system-2024-change-in-production'
    
    # Database configuration - use environment variable for production
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        # Default to SQLite in instance directory for local development
        basedir = os.path.abspath(os.path.dirname(__file__))
        database_url = 'sqlite:///' + os.path.join(basedir, 'instance', 'verxid_system.db')
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'uploads')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Ensure directories exist
    basedir = os.path.abspath(os.path.dirname(__file__))
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(os.path.join(basedir, 'static', 'signatures'), exist_ok=True)
    os.makedirs(os.path.join(basedir, 'static', 'logos'), exist_ok=True)
    os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)
    
    # Import models after db initialization
    from models import User, State, LGA, Ward, Device
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    def load_initial_data():
        """Load initial data from CSV files"""
        import csv
        import os
        
        data_dir = 'data'
        if not os.path.exists(data_dir):
            print("No data directory found, skipping initial data load")
            return
            
        # Load States
        states_file = os.path.join(data_dir, 'states.csv')
        if os.path.exists(states_file) and State.query.count() == 0:
            with open(states_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    state = State(name=row['name'], code=row['code'])
                    db.session.add(state)
            print(f"Loaded {State.query.count()} states")
        
        # Load LGAs
        lgas_file = os.path.join(data_dir, 'lgas.csv')
        if os.path.exists(lgas_file) and LGA.query.count() == 0:
            with open(lgas_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    state = State.query.filter_by(name=row['state_name']).first()
                    if state:
                        lga = LGA(
                            name=row['name'],
                            code=row['lga_code'],
                            state_id=state.id
                        )
                        db.session.add(lga)
            print(f"Loaded {LGA.query.count()} LGAs")
        
        # Load Wards
        wards_file = os.path.join(data_dir, 'wards.csv')
        if os.path.exists(wards_file) and Ward.query.count() == 0:
            with open(wards_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    lga = LGA.query.filter_by(code=row['lga_code']).first()
                    if lga:
                        ward = Ward(
                            name=row['name'],
                            code=row.get('code', ''),
                            lga_id=lga.id
                        )
                        db.session.add(ward)
            print(f"Loaded {Ward.query.count()} wards")
        
        # Load Devices
        devices_file = os.path.join(data_dir, 'devices.csv')
        if os.path.exists(devices_file):
            devices_loaded = 0
            devices_rejected = 0
            rejected_reasons = []
            
            with open(devices_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row_num, row in enumerate(reader, start=2):  # Start at 2 because of header
                    try:
                        state = State.query.filter_by(code=row.get('state_code')).first() if row.get('state_code') else None
                        lga = LGA.query.filter_by(name=row.get('lga_name')).first() if row.get('lga_name') else None
                        
                        # Create device with validation
                        device, errors = Device.create_validated_device(
                            serial_number=row.get('serial_no'),
                            imei1=row.get('imei1'),
                            imei2=row.get('imei2') if row.get('imei2') else None,
                            device_type='tablet',
                            model='VERXID Tablet',
                            manufacturer='VERXID',
                            status='unclaimed',
                            condition='good',
                            state_id=state.id if state else None,
                            lga_id=lga.id if lga else None
                        )
                        
                        if device and not errors:
                            db.session.add(device)
                            devices_loaded += 1
                        else:
                            devices_rejected += 1
                            error_msg = f"Row {row_num} (Serial: {row.get('serial_no', 'N/A')}): {'; '.join(errors)}"
                            rejected_reasons.append(error_msg)
                            
                    except Exception as e:
                        devices_rejected += 1
                        error_msg = f"Row {row_num} (Serial: {row.get('serial_no', 'N/A')}): Unexpected error - {str(e)}"
                        rejected_reasons.append(error_msg)
            
            if devices_loaded > 0:
                print(f"[SUCCESS] Loaded {devices_loaded} new devices")
            else:
                print("[INFO] No new devices to load")
                
            if devices_rejected > 0:
                print(f"[WARNING] Rejected {devices_rejected} devices due to validation errors:")
                for reason in rejected_reasons[:10]:  # Show first 10 errors
                    print(f"   - {reason}")
                if len(rejected_reasons) > 10:
                    print(f"   ... and {len(rejected_reasons) - 10} more errors")
        
        # Load Focals
        focals_file = os.path.join(data_dir, 'focals.csv')
        if os.path.exists(focals_file):
            with open(focals_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Check if user already exists
                    existing_user = User.query.filter_by(email=row['email']).first()
                    if not existing_user:
                        lga = LGA.query.filter_by(name=row['lga_']).first()
                        role_map = {'ALGON': 'algon_focal', 'DCR': 'dcr_focal'}
                        
                        user = User(
                            email=row['email'],
                            username=row['email'].split('@')[0],
                            full_name=row['name'],
                            phone=row['phone_number'],
                            role=role_map.get(row['role'], 'algon_focal'),
                            organization=row['role'],
                            password_hash=generate_password_hash('password123'),  # Default password
                            is_active=True,
                            state_id=lga.state_id if lga else None,
                            lga_id=lga.id if lga else None
                        )
                        db.session.add(user)
            print(f"Loaded focal users")
        
        db.session.commit()
    
    # Register routes
    from routes_new import register_routes
    register_routes(app)
    
    # Create database tables and default user
    with app.app_context():
        db.create_all()
        
        # Load initial data from CSV files
        load_initial_data()
        
        # Create default super admin if doesn't exist
        if not User.query.filter_by(email='druid@druidapps.com').first():
            super_admin = User(
                email='druid@druidapps.com',
                username='druid',
                full_name='Druid Super Administrator',
                role='super_admin',
                password_hash=generate_password_hash('@druid.app.test'),
                is_active=True
            )
            db.session.add(super_admin)
            db.session.commit()
            print("Default super admin created: druid@druidapps.com / @druid.app.test")
    
    return app

if __name__ == '__main__':
    app = create_app()
    print("Starting VERXID System...")
    print("Login: druid@druidapps.com")
    print("Password: @druid.app.test")
    print("URL: http://localhost:5002")
    app.run(debug=True, host='0.0.0.0', port=5002)