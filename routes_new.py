from flask import render_template, request, redirect, url_for, flash, session, jsonify, current_app
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import csv
import json
import base64
from io import StringIO
import pandas as pd

from extensions import db
from models import *
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from io import BytesIO
import base64

def role_required(*roles):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash('Access denied. Insufficient permissions.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

def register_routes(app):
    """Register all routes with the Flask app"""
    
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('login.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            
            user = User.query.filter_by(email=email, is_active=True).first()
            
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'error')
        
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out successfully.', 'success')
        return redirect(url_for('login'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        role = current_user.role
        
        if role == 'super_admin':
            return redirect(url_for('super_admin_dashboard'))
        elif role == 'state_admin':
            return redirect(url_for('state_admin_dashboard'))
        elif role == 'algon_focal':
            return redirect(url_for('algon_dashboard'))
        elif role == 'dcr_focal':
            return redirect(url_for('dcr_witness_dashboard'))
        else:
            flash('Invalid user role', 'error')
            return redirect(url_for('login'))

    # Super Admin Routes
    @app.route('/admin/super')
    @login_required
    @role_required('super_admin')
    def super_admin_dashboard():
        stats = {
            'total_users': User.query.count(),
            'total_devices': Device.query.count(),
            'claimed_devices': Device.query.filter_by(status='claimed').count(),
            'distributed_devices': Device.query.filter_by(status='distributed').count(),
            'total_states': State.query.count(),
            'total_lgas': LGA.query.count()
        }
        return render_template('admin/super_admin_dashboard.html', stats=stats)

    @app.route('/admin/users')
    @login_required
    @role_required('super_admin', 'state_admin')
    def manage_users():
        search = request.args.get('search', '')
        page = request.args.get('page', 1, type=int)
        
        query = User.query
        
        if search:
            query = query.filter(
                db.or_(
                    User.full_name.contains(search),
                    User.email.contains(search),
                    User.username.contains(search)
                )
            )
        
        if current_user.role == 'state_admin':
            query = query.filter_by(state_id=current_user.state_id)
        
        users = query.paginate(
            page=page, per_page=20, error_out=False
        )
        
        return render_template('admin/manage_users.html', users=users, search=search)

    @app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def edit_user(user_id):
        user = User.query.get_or_404(user_id)
        # State admins can only edit users in their own state
        if current_user.role == 'state_admin' and user.state_id != current_user.state_id:
            flash('You do not have permission to edit this user.', 'error')
            return redirect(url_for('manage_users'))

        if request.method == 'POST':
            try:
                user.full_name = request.form['full_name']
                user.username = request.form['username']
                user.email = request.form['email']
                user.phone = request.form.get('phone')
                user.role = request.form['role']
                user.is_active = request.form.get('is_active') == '1'
                
                # State admin restrictions for state_id
                new_state_id = int(request.form.get('state_id')) if request.form.get('state_id') else None
                if current_user.role == 'state_admin' and new_state_id != current_user.state_id:
                    flash('You can only assign users to your assigned state.', 'error')
                    return render_template('admin/edit_user.html', user=user, states=State.query.all())
                user.state_id = new_state_id
                
                # State admin restrictions for lga_id
                if request.form.get('lga_id'):
                    new_lga_id = int(request.form['lga_id'])
                    lga = LGA.query.get_or_404(new_lga_id)
                    if current_user.role == 'state_admin' and lga.state_id != current_user.state_id:
                        flash('You can only assign users to LGAs in your assigned state.', 'error')
                        return render_template('admin/edit_user.html', user=user, states=State.query.all())
                    user.lga_id = new_lga_id
                else:
                    user.lga_id = None
                
                db.session.commit()
                flash(f'User {user.full_name} updated successfully!', 'success')
                return redirect(url_for('manage_users'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating user: {str(e)}', 'error')

        if current_user.role == 'state_admin':
            states = [State.query.get(current_user.state_id)] if current_user.state_id else []
        else:
            states = State.query.all()
        return render_template('admin/edit_user.html', user=user, states=states)

    @app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def delete_user(user_id):
        user = User.query.get_or_404(user_id)
        # Prevent users from deleting themselves
        if user.id == current_user.id:
            flash('You cannot delete your own account.', 'error')
            return redirect(url_for('manage_users'))
        
        # State admins can only delete users in their own state
        if current_user.role == 'state_admin' and user.state_id != current_user.state_id:
            flash('You do not have permission to delete this user.', 'error')
            return redirect(url_for('manage_users'))
            
        try:
            db.session.delete(user)
            db.session.commit()
            flash(f'User {user.full_name} has been deleted.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting user: {str(e)}', 'error')
        
        return redirect(url_for('manage_users'))

    @app.route('/admin/create_user', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def create_user():
        if request.method == 'POST':
            try:
                state_id = int(request.form.get('state_id')) if request.form.get('state_id') else None
                
                # Ensure state admin can only create users in their state
                if current_user.role == 'state_admin' and state_id != current_user.state_id:
                    flash('You can only create users in your assigned state.', 'error')
                    return redirect(url_for('create_user'))
                
                full_name = request.form['full_name']
                user = User(
                    email=request.form['email'],
                    username=request.form['username'],
                    full_name=full_name,
                    phone=request.form.get('phone'),
                    role=request.form['role'],
                    organization=request.form.get('organization'),
                    password_hash=generate_password_hash(request.form['password']),
                    is_active=True
                )
                
                if state_id:
                    user.state_id = state_id
                if request.form.get('lga_id'):
                    lga_id = int(request.form['lga_id'])
                    lga = LGA.query.get_or_404(lga_id)
                    # Ensure state admin can only assign users to LGAs in their state
                    if current_user.role == 'state_admin' and lga.state_id != current_user.state_id:
                        flash('You can only assign users to LGAs in your assigned state.', 'error')
                        return redirect(url_for('create_user'))
                    user.lga_id = lga_id
                    
                db.session.add(user)
                db.session.commit()
                
                flash(f'User {full_name} created successfully!', 'success')
                return redirect(url_for('manage_users'))
                
            except Exception as e:
                flash(f'Error creating user: {str(e)}', 'error')
                db.session.rollback()
        
        if current_user.role == 'state_admin':
            states = [State.query.get(current_user.state_id)] if current_user.state_id else []
            lgas = LGA.query.filter_by(state_id=current_user.state_id).all()
        else:
            states = State.query.all()
            lgas = LGA.query.all()
            
        return render_template('admin/create_user.html', states=states, lgas=lgas)

    @app.route('/admin/devices')
    @login_required
    @role_required('super_admin', 'state_admin')
    def manage_devices():
        search = request.args.get('search', '')
        status_filter = request.args.get('status', '')
        page = request.args.get('page', 1, type=int)
        
        query = Device.query
        
        if search:
            query = query.filter(
                db.or_(
                    Device.serial_number.contains(search),
                    Device.imei1.contains(search),
                    Device.imei2.contains(search),
                    Device.barcode.contains(search)
                )
            )
        
        if status_filter:
            query = query.filter_by(status=status_filter)
        
        if current_user.role == 'state_admin':
            query = query.filter_by(state_id=current_user.state_id)
        
        devices = query.paginate(
            page=page, per_page=20, error_out=False
        )
        
        return render_template('admin/manage_devices.html', 
                             devices=devices, 
                             search=search, 
                             status_filter=status_filter)

    @app.route('/admin/device/edit/<int:device_id>', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def edit_device(device_id):
        device = Device.query.get_or_404(device_id)
        if current_user.role == 'state_admin' and device.state_id != current_user.state_id:
            flash('You do not have permission to edit this device.', 'error')
            return redirect(url_for('manage_devices'))

        if request.method == 'POST':
            try:
                device.serial_number = request.form['serial_number']
                device.device_type = request.form['device_type']
                device.imei1 = request.form['imei1']
                device.imei2 = request.form.get('imei2')
                device.status = request.form['status']
                device.state_id = int(request.form.get('state_id')) if request.form.get('state_id') else None
                device.lga_id = int(request.form.get('lga_id')) if request.form.get('lga_id') else None
                
                db.session.commit()
                flash(f'Device {device.serial_number} updated successfully!', 'success')
                return redirect(url_for('manage_devices'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating device: {str(e)}', 'error')

        states = State.query.all()
        return render_template('admin/edit_device.html', device=device, states=states)

    @app.route('/admin/device/delete/<int:device_id>', methods=['POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def delete_device(device_id):
        device = Device.query.get_or_404(device_id)
        if current_user.role == 'state_admin' and device.state_id != current_user.state_id:
            flash('You do not have permission to delete this device.', 'error')
            return redirect(url_for('manage_devices'))
            
        try:
            db.session.delete(device)
            db.session.commit()
            flash(f'Device {device.serial_number} has been deleted.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting device: {str(e)}', 'error')
        
        return redirect(url_for('manage_devices'))

    @app.route('/admin/data_management')
    @login_required
    @role_required('super_admin', 'state_admin')
    def data_management():
        # Filter data based on user role
        if current_user.role == 'state_admin':
            # State admin can only see their state's data
            state_id = current_user.state_id
            stats = {
                'states': 1,  # Only their state
                'lgas': LGA.query.filter_by(state_id=state_id).count(),
                'wards': Ward.query.join(LGA).filter(LGA.state_id == state_id).count(),
                'focal_persons': User.query.filter(
                    User.role.in_(['algon_focal', 'dcr_focal']),
                    User.state_id == state_id
                ).count(),
                'users': User.query.filter_by(state_id=state_id).count(),
                'devices': Device.query.filter_by(state_id=state_id).count()
            }
        else:
            # Super admin can see all data
            stats = {
                'states': State.query.count(),
                'lgas': LGA.query.count(),
                'wards': Ward.query.count(),
                'focal_persons': User.query.filter(User.role.in_(['algon_focal', 'dcr_focal'])).count(),
                'users': User.query.count(),
                'devices': Device.query.count()
            }
        return render_template('admin/data_management.html', stats=stats)

    @app.route('/admin/states')
    @login_required
    @role_required('super_admin')
    def manage_states():
        states = State.query.all()
        return render_template('admin/manage_states.html', states=states)

    @app.route('/admin/states/add', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin')
    def add_state():
        if request.method == 'POST':
            new_state = State(name=request.form['name'], code=request.form['code'])
            db.session.add(new_state)
            db.session.commit()
            flash('State added successfully!', 'success')
            return redirect(url_for('manage_states'))
        return render_template('admin/state_form.html')

    @app.route('/admin/states/edit/<int:state_id>', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin')
    def edit_state(state_id):
        state = State.query.get_or_404(state_id)
        if request.method == 'POST':
            state.name = request.form['name']
            state.code = request.form['code']
            db.session.commit()
            flash('State updated successfully!', 'success')
            return redirect(url_for('manage_states'))
        return render_template('admin/state_form.html', state=state)

    @app.route('/admin/states/delete/<int:state_id>', methods=['POST'])
    @login_required
    @role_required('super_admin')
    def delete_state(state_id):
        state = State.query.get_or_404(state_id)
        db.session.delete(state)
        db.session.commit()
        flash('State deleted successfully!', 'success')
        return redirect(url_for('manage_states'))

    @app.route('/admin/lgas')
    @login_required
    @role_required('super_admin', 'state_admin')
    def manage_lgas():
        query = LGA.query
        if current_user.role == 'state_admin':
            query = query.filter_by(state_id=current_user.state_id)
        lgas = query.all()
        return render_template('admin/manage_lgas.html', lgas=lgas)

    @app.route('/admin/lgas/add', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def add_lga():
        states = State.query.all()
        if request.method == 'POST':
            new_lga = LGA(name=request.form['name'], code=request.form['code'], state_id=request.form['state_id'])
            db.session.add(new_lga)
            db.session.commit()
            flash('LGA added successfully!', 'success')
            return redirect(url_for('manage_lgas'))
        return render_template('admin/lga_form.html', states=states)

    @app.route('/admin/lgas/edit/<int:lga_id>', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def edit_lga(lga_id):
        lga = LGA.query.get_or_404(lga_id)
        states = State.query.all()
        if request.method == 'POST':
            lga.name = request.form['name']
            lga.code = request.form['code']
            lga.state_id = request.form['state_id']
            db.session.commit()
            flash('LGA updated successfully!', 'success')
            return redirect(url_for('manage_lgas'))
        return render_template('admin/lga_form.html', lga=lga, states=states)

    @app.route('/admin/lgas/delete/<int:lga_id>', methods=['POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def delete_lga(lga_id):
        lga = LGA.query.get_or_404(lga_id)
        db.session.delete(lga)
        db.session.commit()
        flash('LGA deleted successfully!', 'success')
        return redirect(url_for('manage_lgas'))

    @app.route('/admin/wards')
    @login_required
    @role_required('super_admin', 'state_admin')
    def manage_wards():
        query = Ward.query
        if current_user.role == 'state_admin':
            query = query.join(LGA).filter(LGA.state_id == current_user.state_id)
        wards = query.all()
        return render_template('admin/manage_wards.html', wards=wards)

    @app.route('/admin/wards/add', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def add_ward():
        lgas = LGA.query.all()
        if request.method == 'POST':
            new_ward = Ward(name=request.form['name'], lga_id=request.form['lga_id'])
            db.session.add(new_ward)
            db.session.commit()
            flash('Ward added successfully!', 'success')
            return redirect(url_for('manage_wards'))
        return render_template('admin/ward_form.html', lgas=lgas)

    @app.route('/admin/wards/edit/<int:ward_id>', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def edit_ward(ward_id):
        ward = Ward.query.get_or_404(ward_id)
        lgas = LGA.query.all()
        if request.method == 'POST':
            ward.name = request.form['name']
            ward.lga_id = request.form['lga_id']
            db.session.commit()
            flash('Ward updated successfully!', 'success')
            return redirect(url_for('manage_wards'))
        return render_template('admin/ward_form.html', ward=ward, lgas=lgas)

    @app.route('/admin/wards/delete/<int:ward_id>', methods=['POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def delete_ward(ward_id):
        ward = Ward.query.get_or_404(ward_id)
        db.session.delete(ward)
        db.session.commit()
        flash('Ward deleted successfully!', 'success')
        return redirect(url_for('manage_wards'))

    @app.route('/admin/focal_persons')
    @login_required
    @role_required('super_admin', 'state_admin')
    def manage_focal_persons():
        query = User.query.filter(User.role.in_(['algon_focal', 'dcr_focal']))
        if current_user.role == 'state_admin':
            query = query.filter(User.state_id == current_user.state_id)
        persons = query.all()
        return render_template('admin/manage_focal_persons.html', persons=persons)

    @app.route('/admin/focal_persons/add', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def add_focal_person():
        lgas = LGA.query.all()
        if request.method == 'POST':
            lga = LGA.query.get(request.form['lga_id'])
            new_person = User(
                full_name=request.form['full_name'],
                phone=request.form['phone'],
                email=request.form['email'],
                role=request.form['role'],
                lga_id=lga.id,
                state_id=lga.state_id,
                password_hash=generate_password_hash('password123')
            )
            db.session.add(new_person)
            db.session.commit()
            flash('Focal Person added successfully!', 'success')
            return redirect(url_for('manage_focal_persons'))
        return render_template('admin/focal_person_form.html', lgas=lgas)

    @app.route('/admin/focal_persons/edit/<int:person_id>', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def edit_focal_person(person_id):
        person = User.query.get_or_404(person_id)
        lgas = LGA.query.all()
        if request.method == 'POST':
            lga = LGA.query.get(request.form['lga_id'])
            person.full_name = request.form['full_name']
            person.phone = request.form['phone']
            person.email = request.form['email']
            person.role = request.form['role']
            person.lga_id = lga.id
            person.state_id = lga.state_id
            db.session.commit()
            flash('Focal Person updated successfully!', 'success')
            return redirect(url_for('manage_focal_persons'))
        return render_template('admin/focal_person_form.html', person=person, lgas=lgas)

    @app.route('/admin/focal_persons/delete/<int:person_id>', methods=['POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def delete_focal_person(person_id):
        person = User.query.get_or_404(person_id)
        db.session.delete(person)
        db.session.commit()
        flash('Focal Person deleted successfully!', 'success')
        return redirect(url_for('manage_focal_persons'))

    @app.route('/admin/barcode_scanner')
    @login_required
    @role_required('super_admin', 'state_admin')
    def barcode_scanner():
        return render_template('admin/barcode_scanner.html')


    @app.route('/admin/create_device', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def create_device():
        if request.method == 'POST':
            # Logic to create a device will be implemented here
            flash('Device creation functionality is not yet implemented.', 'info')
            return redirect(url_for('manage_devices'))
        states = State.query.all()
        return render_template('admin/create_device.html', states=states)

    @app.route('/admin/csv_upload', methods=['GET', 'POST'])
    @login_required
    @role_required('super_admin', 'state_admin')
    def csv_upload():
        results = None
        if request.method == 'POST':
            if 'csv_file' not in request.files:
                flash('No file part', 'error')
                return redirect(request.url)
            file = request.files['csv_file']
            if file.filename == '':
                flash('No selected file', 'error')
                return redirect(request.url)
            
            if file and file.filename.endswith('.csv'):
                try:
                    # Use StringIO to handle the file in memory
                    csv_file = StringIO(file.stream.read().decode("UTF8"), newline=None)
                    df = pd.read_csv(csv_file)
                    upload_type = request.form.get('upload_type')
                    
                    if upload_type == 'devices':
                        results = process_devices_csv(df)
                    elif upload_type == 'focal_persons':
                        results = process_focals_csv(df)
                    elif upload_type == 'states':
                        results = process_states_csv(df)
                    elif upload_type == 'lgas':
                        results = process_lgas_csv(df)
                    elif upload_type == 'wards':
                        results = process_wards_csv(df)
                    else:
                        flash('Invalid upload type', 'error')
                        return redirect(request.url)

                    flash(f'CSV processed. Success: {results["success"]}, Failed: {len(results["errors"])}', 'info')
                except Exception as e:
                    flash(f'Error processing CSV file: {str(e)}', 'error')
                return render_template('admin/csv_upload.html', results=results)

        return render_template('admin/csv_upload.html', results=results)

    # Logo Management Routes
    @app.route('/admin/manage_logos')
    @login_required
    @role_required('super_admin')
    def manage_logos():
        logos = SystemLogo.query.all()
        return render_template('admin/manage_logos.html', logos=logos)
    
    @app.route('/admin/upload_logo', methods=['POST'])
    @login_required
    @role_required('super_admin')
    def upload_logo():
        try:
            organization = request.form.get('organization')
            if 'logo_file' not in request.files:
                flash('No file selected', 'error')
                return redirect(url_for('manage_logos'))
            
            file = request.files['logo_file']
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(url_for('manage_logos'))
            
            # Check if organization logo already exists
            existing_logo = SystemLogo.query.filter_by(organization=organization).first()
            if existing_logo:
                # Update existing logo
                existing_logo.logo_filename = file.filename
                existing_logo.logo_data = file.read()
                existing_logo.content_type = file.content_type
                existing_logo.uploaded_by = current_user.id
                existing_logo.upload_date = datetime.utcnow()
                flash(f'{organization} logo updated successfully', 'success')
            else:
                # Create new logo entry
                logo = SystemLogo(
                    organization=organization,
                    logo_filename=file.filename,
                    logo_data=file.read(),
                    content_type=file.content_type,
                    uploaded_by=current_user.id
                )
                db.session.add(logo)
                flash(f'{organization} logo uploaded successfully', 'success')
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error uploading logo: {str(e)}', 'error')
        
        return redirect(url_for('manage_logos'))

    @app.route('/admin/logo/<int:logo_id>')
    @login_required
    def get_logo(logo_id):
        logo = SystemLogo.query.get_or_404(logo_id)
        return app.response_class(
            logo.logo_data,
            mimetype=logo.content_type,
            headers={"Content-Disposition": f"inline; filename={logo.logo_filename}"}
        )

    # Focal Person Routes
    @app.route('/focal/algon')
    @login_required
    @role_required('algon_focal')
    def algon_dashboard():
        # Get all devices for this LGA that are available to this focal person
        # This includes both assigned devices and unclaimed devices in the LGA
        lga_devices = Device.query.filter_by(lga_id=current_user.lga_id).all()
        
        # Filter devices that are either assigned to this focal or are unclaimed
        available_devices = [d for d in lga_devices if d.assigned_focal_id == current_user.id or d.status == 'unclaimed']
        
        stats = {
            'total_available': len(available_devices),
            'unclaimed': len([d for d in available_devices if d.status == 'unclaimed']),
            'claimed': len([d for d in available_devices if d.status == 'claimed']),
            'distributed': len([d for d in available_devices if d.status == 'distributed'])
        }
        
        # Get total number of wards in this LGA for sign-off logic
        total_wards = Ward.query.filter_by(lga_id=current_user.lga_id).count()
        
        return render_template('focal/algon_dashboard.html', devices=available_devices, stats=stats, total_wards=total_wards)

    @app.route('/focal/sign_off_claims', methods=['POST'])
    @login_required
    @role_required('algon_focal')
    def sign_off_claims():
        lga_id = request.form.get('lga_id')
        
        # Verify this is the focal's LGA
        if int(lga_id) != current_user.lga_id:
            flash('You can only sign-off claims for your assigned LGA.', 'error')
            return redirect(url_for('algon_dashboard'))
        
        # Check if all wards are covered
        total_wards = Ward.query.filter_by(lga_id=current_user.lga_id).count()
        distributed_devices = Device.query.filter_by(lga_id=current_user.lga_id, status='distributed').count()
        
        if distributed_devices < total_wards:
            flash(f'Cannot sign-off claims. You have distributed {distributed_devices} devices but need to cover all {total_wards} wards.', 'error')
            return redirect(url_for('algon_dashboard'))
        
        # TODO: Implement actual sign-off logic here
        # This could involve updating device records, creating audit logs, etc.
        
        flash(f'Successfully signed-off claims for {distributed_devices} devices across {total_wards} wards.', 'success')
        return redirect(url_for('algon_dashboard'))

    # Comprehensive Reports Endpoint
    @app.route('/reports')
    @login_required
    def reports_center():
        """Centralized reports endpoint for all PDF downloads"""
        user_role = current_user.role
        user_state_id = current_user.state_id
        user_lga_id = current_user.lga_id
        
        # Get available report types based on user role
        available_reports = []
        
        if user_role in ['super_admin', 'state_admin']:
            # State-level reports - only show states with devices
            if user_role == 'super_admin':
                # Super admin can generate reports for all states that have devices
                states = db.session.query(State).join(Device).filter(Device.state_id == State.id).distinct().all()
            else:
                # State admin can only generate reports for their state if it has devices
                if current_user.state and Device.query.filter_by(state_id=current_user.state.id).first():
                    states = [current_user.state]
                else:
                    states = []
            
            for state in states:
                available_reports.extend([
                    {
                        'title': f'{state.name} State Receipt Form',
                        'description': 'Official receipt form for state-level device distribution',
                        'url': url_for('generate_state_receipt_pdf', state_id=state.id),
                        'icon': 'fas fa-receipt',
                        'category': 'State Reports',
                        'state': state.name
                    },
                    {
                        'title': f'{state.name} State Assignment Form',
                        'description': 'Device assignment form for LGA distribution authorization',
                        'url': url_for('generate_state_assignment_pdf', state_id=state.id),
                        'icon': 'fas fa-clipboard-check',
                        'category': 'State Reports',
                        'state': state.name
                    },
                    {
                        'title': f'{state.name} State Summary Report',
                        'description': 'Comprehensive summary of device distribution in the state',
                        'url': url_for('generate_state_summary_pdf', state_id=state.id),
                        'icon': 'fas fa-chart-bar',
                        'category': 'State Reports',
                        'state': state.name
                    },
                    {
                        'title': f'{state.name} Comprehensive Distribution Report',
                        'description': 'Complete distribution breakdown by LGA and ward',
                        'url': url_for('generate_comprehensive_distribution_pdf', state_id=state.id),
                        'icon': 'fas fa-list-alt',
                        'category': 'State Reports',
                        'state': state.name
                    }
                ])
        
        if user_role == 'algon_focal' and user_lga_id:
            # LGA-level reports for ALGON focal - only if they have devices
            lga = current_user.lga
            if lga and Device.query.filter_by(lga_id=lga.id).first():
                available_reports.extend([
                    {
                        'title': f'{lga.name} LGA Distribution Report',
                        'description': 'Device distribution report for this LGA',
                        'url': url_for('generate_lga_distribution_pdf', lga_id=lga.id),
                        'icon': 'fas fa-map-marked-alt',
                        'category': 'LGA Reports',
                        'lga': lga.name
                    }
                ])
                
                # Individual device reports
                distributed_devices = Device.query.filter_by(
                    lga_id=user_lga_id, 
                    status='distributed'
                ).all()
                
                for device in distributed_devices:
                    available_reports.append({
                        'title': f'Device {device.serial_number or device.imei1} Issuance Form',
                        'description': f'Individual issuance form for device distributed to {device.recipient_name or "Unknown"}',
                        'url': url_for('generate_device_issuance_pdf', device_id=device.id),
                        'icon': 'fas fa-file-alt',
                        'category': 'Individual Device Forms',
                        'device': device.serial_number or device.imei1
                    })
        
        # Group reports by category
        grouped_reports = {}
        for report in available_reports:
            category = report['category']
            if category not in grouped_reports:
                grouped_reports[category] = []
            grouped_reports[category].append(report)
        
        return render_template('reports/reports_center.html', 
                             grouped_reports=grouped_reports,
                             user_role=user_role,
                             user_name=current_user.full_name)

    @app.route('/dcr/witness')
    @login_required
    @role_required('dcr_focal')
    def dcr_witness_dashboard():
        # This logic needs to be more specific based on how claims are associated with DCRs
        pending_claims = DeviceClaim.query.filter_by(status='pending').all()
        return render_template('focal/dcr_dashboard.html', pending_claims=pending_claims)

    # Password Reset Routes
    @app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
    @login_required
    @role_required('super_admin')
    def reset_user_password(user_id):
        user = User.query.get_or_404(user_id)
        user.password_hash = generate_password_hash('password123')
        db.session.commit()
        flash(f'Password reset to "password123" for {user.full_name}', 'success')
        return redirect(url_for('manage_users'))

    # Change Password Routes
    @app.route('/change_password', methods=['GET', 'POST'])
    @login_required
    def change_password():
        if request.method == 'POST':
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            
            # Verify current password
            if not check_password_hash(current_user.password_hash, current_password):
                flash('Current password is incorrect', 'error')
                return render_template('auth/change_password.html')
            
            # Verify new passwords match
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return render_template('auth/change_password.html')
            
            # Update password
            current_user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('Password changed successfully', 'success')
            return redirect(url_for('dashboard'))
        
        return render_template('auth/change_password.html')

    # Device Management Routes for ALGON Focals
    @app.route('/focal/claim_device', methods=['POST'])
    @login_required
    @role_required('algon_focal')
    def claim_device():
        device_id = request.form.get('device_id')
        device = Device.query.get_or_404(device_id)
        
        # Verify the device is in the user's LGA and is unclaimed
        if device.lga_id != current_user.lga_id:
            flash('You can only claim devices in your LGA', 'error')
            return redirect(url_for('algon_dashboard'))
        
        if device.status != 'unclaimed':
            flash('This device has already been claimed', 'error')
            return redirect(url_for('algon_dashboard'))
        
        # Claim the device
        device.status = 'claimed'
        device.assigned_focal_id = current_user.id
        device.claimed_at = datetime.utcnow()
        db.session.commit()
        
        flash(f'Device {device.serial_number or device.imei1} claimed successfully', 'success')
        return redirect(url_for('algon_dashboard'))

    @app.route('/focal/distribute/<int:device_id>')
    @login_required
    @role_required('algon_focal')
    def distribute_device_form(device_id):
        device = Device.query.get_or_404(device_id)
        
        # Verify the device belongs to this focal person and is claimed
        if device.assigned_focal_id != current_user.id or device.status != 'claimed':
            flash('You can only distribute devices you have claimed', 'error')
            return redirect(url_for('algon_dashboard'))
        
        # Get wards in this LGA for distribution
        wards = Ward.query.filter_by(lga_id=current_user.lga_id).all()
        
        from datetime import datetime
        return render_template('focal/distribute_device.html', device=device, wards=wards, current_date=datetime.now())
    
    @app.route('/focal/distribute', methods=['POST'])
    @login_required
    @role_required('algon_focal')
    def distribute_device():
        try:
            device_id = request.form.get('device_id')
            device = Device.query.get_or_404(device_id)
            
            # Verify permissions
            if device.assigned_focal_id != current_user.id or device.status != 'claimed':
                return jsonify({'success': False, 'error': 'You can only distribute devices you have claimed'})
            
            # Extract form data according to Digital Device Issuance Form structure
            form_data = {
                # Section A: Device Information (already in device record)
                'accessories': {
                    'charger': 'charger' in request.form.getlist('accessories'),
                    'charger_qty': int(request.form.get('charger_qty', 0)) if request.form.get('charger_qty') else 0,
                    'power_cable': 'power_cable' in request.form.getlist('accessories'),
                    'power_cable_qty': int(request.form.get('power_cable_qty', 0)) if request.form.get('power_cable_qty') else 0,
                    'sim_card': 'sim_card' in request.form.getlist('accessories'),
                    'sim_network': request.form.get('sim_network', ''),
                    'sim_number': request.form.get('sim_number', ''),
                    'protective_case': 'protective_case' in request.form.getlist('accessories'),
                    'protective_case_qty': int(request.form.get('protective_case_qty', 0)) if request.form.get('protective_case_qty') else 0,
                    'stylus_pen': 'stylus_pen' in request.form.getlist('accessories'),
                    'stylus_pen_qty': int(request.form.get('stylus_pen_qty', 0)) if request.form.get('stylus_pen_qty') else 0,
                    'user_manual': 'user_manual' in request.form.getlist('accessories'),
                    'user_manual_qty': int(request.form.get('user_manual_qty', 0)) if request.form.get('user_manual_qty') else 0,
                    'other': 'other' in request.form.getlist('accessories'),
                    'other_specify': request.form.get('other_specify', ''),
                    'other_qty': int(request.form.get('other_qty', 0)) if request.form.get('other_qty') else 0,
                },
                'device_condition': request.form.get('device_condition'),
                'device_defects': request.form.get('device_defects', ''),
                
                # Section B: Recipient Information
                'recipient_name': request.form.get('recipient_name'),
                'recipient_designation': request.form.get('recipient_designation'),
                'staff_id': request.form.get('staff_id', ''),
                'registration_center_name': request.form.get('registration_center_name'),
                'registration_center_address': request.form.get('registration_center_address'),
                'recipient_phone': request.form.get('recipient_phone'),
                'recipient_email': request.form.get('recipient_email', ''),
                
                # Section C: Issuing Authority (auto-populated from current user)
                'issuer_name': current_user.full_name,
                'issuer_title': 'ALGON Focal Person',
                'issuing_office': f"{current_user.lga.name if current_user.lga else 'N/A'}, {current_user.state.name if current_user.state else 'N/A'}",
                'issuance_date': datetime.utcnow(),
                
                # Section D: Terms Acceptance
                'terms_accepted': request.form.get('terms_accepted') == 'on',
                
                # Section E: Signatures
                'recipient_signature': request.form.get('recipient_signature'),
                'issuer_signature': request.form.get('issuer_signature'),
                'witness_signature': request.form.get('witness_signature'),
                'witness_name': request.form.get('witness_name'),
                'witness_role': request.form.get('witness_role'),
            }
            
            # Create a comprehensive device issuance record
            # You might want to create a new DeviceIssuance model for this, but for now, update the device
            device.status = 'distributed'
            device.distributed_at = datetime.utcnow()
            device.recipient_name = form_data['recipient_name']
            device.recipient_phone = form_data['recipient_phone']
            device.recipient_designation = form_data['recipient_designation']
            device.registration_center_name = form_data['registration_center_name']
            device.registration_center_address = form_data['registration_center_address']
            device.staff_id = form_data['staff_id']
            device.recipient_email = form_data['recipient_email']
            device.device_condition = form_data['device_condition']
            device.device_defects = form_data['device_defects']
            device.accessories_data = json.dumps(form_data['accessories'])
            device.terms_accepted = form_data['terms_accepted']
            device.recipient_signature_data = form_data['recipient_signature']
            device.issuer_signature_data = form_data['issuer_signature']
            device.witness_signature_data = form_data['witness_signature']
            device.witness_name = form_data['witness_name']
            device.witness_role = form_data['witness_role']
            
            db.session.commit()
            
            # Save issuer signature for future use if not already saved
            if not current_user.signature_data and form_data['issuer_signature']:
                current_user.signature_data = form_data['issuer_signature']
                db.session.commit()
            
            return jsonify({
                'success': True, 
                'message': f'Device {device.serial_number or device.imei1} distributed successfully to {form_data["recipient_name"]}'
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/focal/edit_device/<int:device_id>', methods=['GET', 'POST'])
    @login_required
    @role_required('algon_focal')
    def focal_edit_device(device_id):
        device = Device.query.get_or_404(device_id)
        
        # Check if user can edit this device
        if device.status != 'unclaimed' or (device.assigned_focal_id and device.assigned_focal_id != current_user.id):
            flash('You can only edit unclaimed devices assigned to you.', 'error')
            return redirect(url_for('algon_dashboard'))
        
        if request.method == 'POST':
            try:
                device.serial_number = request.form['serial_number']
                device.imei1 = request.form['imei1']
                device.imei2 = request.form.get('imei2', '').strip() or None
                device.model = request.form.get('model', 'VERXID Tablet')
                device.device_type = request.form.get('device_type', 'Tablet')
                
                db.session.commit()
                flash('Device updated successfully!', 'success')
                return redirect(url_for('algon_dashboard'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating device: {str(e)}', 'error')
        
        return render_template('focal/edit_device.html', device=device)

    @app.route('/focal/reject_device', methods=['POST'])
    @login_required
    @role_required('algon_focal')
    def focal_reject_device():
        try:
            device_id = request.form.get('device_id')
            rejection_reason = request.form.get('rejection_reason', '').strip()
            
            device = Device.query.get_or_404(device_id)
            
            # Check if user can reject this device
            if device.status != 'unclaimed':
                return jsonify({'success': False, 'error': 'You can only reject unclaimed devices'})
            
            if not rejection_reason:
                return jsonify({'success': False, 'error': 'Rejection reason is required'})
            
            # Update device status and add rejection details
            device.status = 'rejected'
            device.rejection_reason = rejection_reason
            device.rejected_at = datetime.utcnow()
            device.rejected_by_id = current_user.id
            
            db.session.commit()
            
            flash(f'Device {device.serial_number or device.imei1} rejected successfully', 'success')
            return redirect(url_for('algon_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error rejecting device: {str(e)}', 'error')
            return redirect(url_for('algon_dashboard'))

    def process_devices_csv(df):
        errors = []
        success_count = 0
        for index, row in df.iterrows():
            try:
                if not all(k in row and pd.notna(row[k]) for k in ['serial_number', 'imei1', 'imei2']):
                    raise ValueError("Missing required fields: serial_number, imei1, imei2")

                if Device.query.filter_by(serial_number=str(row['serial_number'])).first():
                    raise ValueError(f"Serial number {row['serial_number']} already exists")
                if Device.query.filter_by(imei1=str(row['imei1'])).first():
                    raise ValueError(f"IMEI1 {row['imei1']} already exists")
                if Device.query.filter_by(imei2=str(row['imei2'])).first():
                    raise ValueError(f"IMEI2 {row['imei2']} already exists")

                state = State.query.filter_by(code=row.get('state_code')).first()
                lga = LGA.query.filter_by(code=row.get('lga_code')).first() if state else None

                device = Device(
                    serial_number=str(row.get('serial_number')),
                    imei1=str(row.get('imei1')),
                    imei2=str(row.get('imei2')),
                    device_type=row.get('device_type', 'VERXID Tablet'),
                    state_id=state.id if state else None,
                    lga_id=lga.id if lga else None
                )
                db.session.add(device)
                success_count += 1
            except Exception as e:
                errors.append({'row': index + 2, 'message': str(e)})
        db.session.commit()
        return {'success': success_count, 'errors': errors}

    def process_focals_csv(df):
        errors = []
        success_count = 0
        for index, row in df.iterrows():
            try:
                # Check required fields including new NIN and email fields
                required_fields = ['name', 'phone', 'lga_code', 'state_code', 'role_type', 'nin', 'email']
                if not all(k in row and pd.notna(row[k]) for k in required_fields):
                    missing_fields = [f for f in required_fields if f not in row or pd.isna(row[f])]
                    raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")

                email = str(row['email']).strip()
                phone = str(row['phone']).strip()
                nin = str(row['nin']).strip()

                # Validate NIN (should be 11 digits)
                if len(nin) != 11 or not nin.isdigit():
                    raise ValueError(f"NIN must be exactly 11 digits, got: {nin}")

                state = State.query.filter_by(code=row['state_code']).first()
                if not state: raise ValueError(f"State with code '{row['state_code']}' not found")
                
                lga = LGA.query.filter_by(code=row['lga_code'], state_id=state.id).first()
                if not lga: raise ValueError(f"LGA with code '{row['lga_code']}' not found in state '{state.name}'")

                # Check for existing user by email or phone
                if User.query.filter_by(email=email).first():
                    raise ValueError(f"User with email {email} already exists")
                if User.query.filter_by(phone=phone).first():
                    raise ValueError(f"User with phone {phone} already exists")
                
                # Check for existing NIN in FocalPerson table
                if FocalPerson.query.filter_by(nin=nin).first():
                    raise ValueError(f"Focal person with NIN {nin} already exists")

                # Create User account
                user = User(
                    full_name=row['name'],
                    username=email, # Use email as username
                    email=email,
                    phone=phone,
                    lga_id=lga.id,
                    state_id=state.id,
                    role=str(row['role_type']).lower() + '_focal',
                    password_hash=generate_password_hash('password123'),
                    is_active=True
                )
                db.session.add(user)
                db.session.flush()  # Get user ID
                
                # Create FocalPerson record with new fields
                focal_person = FocalPerson(
                    name=row['name'],
                    phone=phone,
                    email=email,
                    lga_id=lga.id,
                    role_type=str(row['role_type']).upper(),
                    organization=row.get('organization') if pd.notna(row.get('organization')) else None,
                    nin=nin,
                    bank_name=row.get('bank_name') if pd.notna(row.get('bank_name')) else None,
                    account_number=str(row.get('account_number')) if pd.notna(row.get('account_number')) else None,
                    user_id=user.id,
                    is_active=True
                )
                db.session.add(focal_person)
                success_count += 1
            except Exception as e:
                db.session.rollback() # Rollback on error for this row
                errors.append({'row': index + 2, 'message': str(e)})
        db.session.commit()
        return {'success': success_count, 'errors': errors}

    def process_states_csv(df):
        errors = []
        success_count = 0
        for index, row in df.iterrows():
            try:
                if not all(k in row and pd.notna(row[k]) for k in ['name', 'code']):
                    raise ValueError("Missing required fields: name, code")
                if State.query.filter_by(code=row['code']).first():
                    raise ValueError(f"State with code {row['code']} already exists")
                state = State(name=row['name'], code=row['code'])
                db.session.add(state)
                success_count += 1
            except Exception as e:
                errors.append({'row': index + 2, 'message': str(e)})
        db.session.commit()
        return {'success': success_count, 'errors': errors}

    def process_lgas_csv(df):
        errors = []
        success_count = 0
        for index, row in df.iterrows():
            try:
                if not all(k in row and pd.notna(row[k]) for k in ['name', 'code', 'state_code']):
                    raise ValueError("Missing required fields: name, code, state_code")
                state = State.query.filter_by(code=row['state_code']).first()
                if not state: raise ValueError(f"State with code '{row['state_code']}' not found")
                if LGA.query.filter_by(code=row['code'], state_id=state.id).first():
                    raise ValueError(f"LGA with code {row['code']} already exists in {state.name}")
                lga = LGA(name=row['name'], code=row['code'], state_id=state.id)
                db.session.add(lga)
                success_count += 1
            except Exception as e:
                errors.append({'row': index + 2, 'message': str(e)})
        db.session.commit()
        return {'success': success_count, 'errors': errors}

    def process_wards_csv(df):
        errors = []
        success_count = 0
        for index, row in df.iterrows():
            try:
                # Basic ward information (required)
                required_fields = ['name', 'lga_code', 'state_code']
                if not all(k in row and pd.notna(row[k]) for k in required_fields):
                    raise ValueError(f"Missing required fields: {', '.join(required_fields)}")
                
                state = State.query.filter_by(code=row['state_code']).first()
                if not state: raise ValueError(f"State with code '{row['state_code']}' not found")
                
                lga = LGA.query.filter_by(code=row['lga_code'], state_id=state.id).first()
                if not lga: raise ValueError(f"LGA with code '{row['lga_code']}' not found in state '{state.name}'")
                
                if Ward.query.filter_by(name=row['name'], lga_id=lga.id).first():
                    raise ValueError(f"Ward '{row['name']}' already exists in LGA '{lga.name}'")
                
                # Validate ward officer NIN if provided
                ward_officer_nin = None
                if pd.notna(row.get('ward_officer_nin')):
                    ward_officer_nin = str(row['ward_officer_nin']).strip()
                    if len(ward_officer_nin) != 11 or not ward_officer_nin.isdigit():
                        raise ValueError(f"Ward officer NIN must be exactly 11 digits, got: {ward_officer_nin}")
                    # Check for duplicate NIN
                    if Ward.query.filter_by(ward_officer_nin=ward_officer_nin).first():
                        raise ValueError(f"Ward officer with NIN {ward_officer_nin} already exists")
                
                # Create ward with all available fields
                ward = Ward(
                    name=row['name'],
                    lga_id=lga.id,
                    code=row.get('code') if pd.notna(row.get('code')) else None,
                    # Ward officer basic information
                    ward_officer_name=row.get('ward_officer_name') if pd.notna(row.get('ward_officer_name')) else None,
                    ward_officer_phone=str(row.get('ward_officer_phone')) if pd.notna(row.get('ward_officer_phone')) else None,
                    ward_officer_email=row.get('ward_officer_email') if pd.notna(row.get('ward_officer_email')) else None,
                    ward_officer_staff_id=str(row.get('ward_officer_staff_id')) if pd.notna(row.get('ward_officer_staff_id')) else None,
                    ward_officer_designation=row.get('ward_officer_designation') if pd.notna(row.get('ward_officer_designation')) else None,
                    # Ward officer banking and identification
                    ward_officer_nin=ward_officer_nin,
                    ward_officer_bank_name=row.get('ward_officer_bank_name') if pd.notna(row.get('ward_officer_bank_name')) else None,
                    ward_officer_account_number=str(row.get('ward_officer_account_number')) if pd.notna(row.get('ward_officer_account_number')) else None,
                    # Registration center information
                    registration_center_name=row.get('registration_center_name') if pd.notna(row.get('registration_center_name')) else None,
                    registration_center_address=row.get('registration_center_address') if pd.notna(row.get('registration_center_address')) else None
                )
                db.session.add(ward)
                success_count += 1
            except Exception as e:
                errors.append({'row': index + 2, 'message': str(e)})
        db.session.commit()
        return {'success': success_count, 'errors': errors}

    @app.route('/admin/process_scanned_items', methods=['POST'])
    @login_required
    def process_scanned_items():
        return jsonify({'success': False, 'error': 'Not implemented'})

    @app.route('/admin/csv_template/<template_type>')
    @login_required
    @role_required('super_admin', 'state_admin')
    def download_csv_template(template_type):
        """Generate and serve CSV template files with reference data"""
        import io
        import csv
        from flask import Response
        
        # For state admin, filter by their state
        if current_user.role == 'state_admin':
            user_state = current_user.state_id
        else:
            user_state = None
        
        if template_type == 'focals':
            # Get states and LGAs with reference data
            states = State.query.all() if user_state is None else [current_user.state]
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write headers with enhanced reference data
            writer.writerow(['name', 'phone', 'email', 'lga_code', 'state_code', 'role_type', 'nin', 'bank_name', 'account_number'])
            writer.writerow([])  # Blank row for separation
            writer.writerow(['# Reference Data - States and LGAs'])
            writer.writerow(['# State Code', 'State Name', 'LGA Code', 'LGA Name'])
            
            for state in states:
                lgas = LGA.query.filter_by(state_id=state.id).all()
                for lga in lgas:
                    writer.writerow([f'# {state.code}', state.name, lga.code, lga.name])
            
            writer.writerow([])
            writer.writerow(['# Sample Data (role_type must be ALGON or DCR)'])
            writer.writerow(['John Doe', '08012345678', 'john@email.com', 'ABA01', 'AB', 'ALGON', '12345678901', 'GTBank', '0123456789'])
            
            output.seek(0)
            return Response(output.getvalue(),
                          mimetype='text/csv',
                          headers={'Content-Disposition': 'attachment;filename=focals_template.csv'})
                          
        elif template_type == 'wards':
            # Get wards template with state/LGA reference
            states = State.query.all() if user_state is None else [current_user.state]
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            writer.writerow(['name', 'lga_code', 'state_code', 'ward_officer_name', 'ward_officer_nin', 'registration_center_name'])
            writer.writerow([])
            writer.writerow(['# Reference Data - States, LGAs and existing Wards'])
            writer.writerow(['# State Code', 'State Name', 'LGA Code', 'LGA Name', 'Existing Wards'])
            
            for state in states:
                lgas = LGA.query.filter_by(state_id=state.id).all()
                for lga in lgas:
                    existing_wards = Ward.query.filter_by(lga_id=lga.id).all()
                    ward_names = ', '.join([w.name for w in existing_wards[:3]])  # Show first 3
                    if len(existing_wards) > 3:
                        ward_names += f' (+{len(existing_wards)-3} more)'
                    writer.writerow([f'# {state.code}', state.name, lga.code, lga.name, ward_names])
            
            writer.writerow([])
            writer.writerow(['# Sample Data'])
            writer.writerow(['Ward 1', 'ABA01', 'AB', 'Jane Smith', '09876543210', 'Central Registration Center'])
            
            output.seek(0)
            return Response(output.getvalue(),
                          mimetype='text/csv',
                          headers={'Content-Disposition': 'attachment;filename=wards_template.csv'})
                          
        elif template_type == 'devices':
            # Get devices template with state/LGA reference
            states = State.query.all() if user_state is None else [current_user.state]
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            writer.writerow(['serial_number', 'imei1', 'imei2', 'device_type', 'model', 'manufacturer', 'state_code', 'lga_code', 'carton_number', 'barcode'])
            writer.writerow([])
            writer.writerow(['# Reference Data - Valid State and LGA Codes'])
            writer.writerow(['# State Code', 'State Name', 'LGA Code', 'LGA Name'])
            
            for state in states:
                lgas = LGA.query.filter_by(state_id=state.id).all()
                for lga in lgas:
                    writer.writerow([f'# {state.code}', state.name, lga.code, lga.name])
            
            writer.writerow([])
            writer.writerow(['# Sample Data'])
            writer.writerow(['VRX001TAB', '123456789012345', '123456789012346', 'Tablet', 'VERXID V1', 'TechCorp', 'AB', 'ABA01', 'CTN001', 'VRX001'])
            
            output.seek(0)
            return Response(output.getvalue(),
                          mimetype='text/csv',
                          headers={'Content-Disposition': 'attachment;filename=devices_template.csv'})
                          
        elif template_type == 'states':
            output = io.StringIO()
            writer = csv.writer(output)
            
            writer.writerow(['name', 'code'])
            writer.writerow([])
            writer.writerow(['# Sample Data'])
            writer.writerow(['Abia', 'AB'])
            writer.writerow(['Lagos', 'LA'])
            
            output.seek(0)
            return Response(output.getvalue(),
                          mimetype='text/csv',
                          headers={'Content-Disposition': 'attachment;filename=states_template.csv'})
                          
        elif template_type == 'lgas':
            # Get states for reference
            states = State.query.all() if user_state is None else [current_user.state]
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            writer.writerow(['name', 'code', 'state_code'])
            writer.writerow([])
            writer.writerow(['# Reference Data - Available States'])
            writer.writerow(['# State Code', 'State Name'])
            
            for state in states:
                writer.writerow([f'# {state.code}', state.name])
            
            writer.writerow([])
            writer.writerow(['# Sample Data'])
            writer.writerow(['Aba North', 'ABA01', 'AB'])
            writer.writerow(['Aba South', 'ABA02', 'AB'])
            
            output.seek(0)
            return Response(output.getvalue(),
                          mimetype='text/csv',
                          headers={'Content-Disposition': 'attachment;filename=lgas_template.csv'})
        
        return jsonify({'error': 'Template not found'}), 404

    @app.route('/admin/distribution')
    @login_required
    def device_distribution():
        devices = Device.query.filter_by(status='claimed').all()
        states = State.query.all()
        return render_template('admin/distribution.html', devices=devices, states=states)
        
    # State Admin Routes
    @app.route('/admin/state_admin_dashboard')
    @login_required
    @role_required('state_admin')
    def state_admin_dashboard():
        stats = {
            'total_users': User.query.filter_by(state_id=current_user.state_id).count(),
            'total_devices': Device.query.filter_by(state_id=current_user.state_id).count(),
            'claimed_devices': Device.query.filter_by(state_id=current_user.state_id, status='claimed').count(),
            'distributed_devices': Device.query.filter_by(state_id=current_user.state_id, status='distributed').count(),
            'total_lgas': LGA.query.filter_by(state_id=current_user.state_id).count()
        }
        return render_template('admin/state_admin_dashboard.html', stats=stats)


    @app.route('/api/wards/<int:lga_id>')
    @login_required
    def get_wards_for_lga(lga_id):
        wards = Ward.query.filter_by(lga_id=lga_id).all()
        return jsonify([{'id': ward.id, 'name': ward.name} for ward in wards])

    @app.route('/api/witnesses/<int:ward_id>')
    @login_required
    def get_witnesses_for_ward(ward_id):
        # This is a placeholder, logic needs to be defined
        return jsonify([])

    @app.route('/dcr/witness_claim/<int:claim_id>', methods=['POST'])
    @login_required
    def witness_claim(claim_id):
        return jsonify({'success': False, 'error': 'Not implemented'})

    @app.route('/dcr/bulk_witness_claims', methods=['POST'])
    @login_required
    def bulk_witness_claims():
        return jsonify({'success': False, 'error': 'Not implemented'})

    # API Routes
    @app.route('/api/states', methods=['GET', 'POST'])
    @login_required
    def api_states():
        if request.method == 'POST':
            if current_user.role != 'super_admin':
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            data = request.get_json()
            if not data or not data.get('name') or not data.get('code'):
                return jsonify({'success': False, 'error': 'Missing data'}), 400
            
            new_state = State(name=data['name'], code=data['code'])
            db.session.add(new_state)
            db.session.commit()
            return jsonify({'success': True, 'state': {'id': new_state.id, 'name': new_state.name, 'code': new_state.code}})

        states = State.query.all()
        return jsonify([{'id': state.id, 'name': state.name, 'code': state.code} for state in states])

    @app.route('/api/lgas', methods=['GET', 'POST'])
    @login_required
    def api_lgas():
        if request.method == 'POST':
            data = request.get_json()
            if not data or not data.get('name') or not data.get('code') or not data.get('state_id'):
                return jsonify({'success': False, 'error': 'Missing data'}), 400
            
            new_lga = LGA(
                name=data['name'], 
                code=data['code'], 
                state_id=data['state_id'],
                chairman_name=data.get('chairman_name'),
                chairman_phone=data.get('chairman_phone')
            )
            db.session.add(new_lga)
            db.session.commit()
            return jsonify({'success': True, 'lga': {'id': new_lga.id, 'name': new_lga.name, 'code': new_lga.code}})

        query = LGA.query
        if current_user.role == 'state_admin':
            query = query.filter_by(state_id=current_user.state_id)
        lgas = query.all()
        return jsonify([lga.to_dict() for lga in lgas])

    @app.route('/api/wards', methods=['GET', 'POST'])
    @login_required
    def api_wards():
        if request.method == 'POST':
            data = request.get_json()
            if not data or not data.get('name') or not data.get('lga_id'):
                return jsonify({'success': False, 'error': 'Missing data'}), 400

            new_ward = Ward(
                name=data['name'],
                lga_id=data['lga_id'],
                code=data.get('code'),
                ward_officer_name=data.get('ward_officer_name'),
                ward_officer_phone=data.get('ward_officer_phone')
            )
            db.session.add(new_ward)
            db.session.commit()
            return jsonify({'success': True, 'ward': new_ward.to_dict()})

        wards = Ward.query.all()
        return jsonify([ward.to_dict() for ward in wards])

    @app.route('/api/focal_persons', methods=['GET', 'POST'])
    @login_required
    def api_focal_persons():
        if request.method == 'POST':
            data = request.get_json()
            # Basic validation
            if not all(k in data for k in ['name', 'phone', 'lga_id', 'role_type']):
                return jsonify({'success': False, 'error': 'Missing required fields'}), 400
            
            # Find user by a unique identifier if they exist, or create a new one
            user = User.query.filter_by(phone=data['phone']).first()
            if not user:
                user = User(
                    full_name=data['name'],
                    phone=data['phone'],
                    email=data.get('email'),
                    lga_id=data['lga_id'],
                    role=data['role_type'].lower() + '_focal', # e.g., ALGON -> algon_focal
                    organization=data.get('organization'),
                    is_active=True,
                    # Set a default or random password
                    password_hash=generate_password_hash('password123') 
                )
                db.session.add(user)
                flash(f'New user created for {user.full_name} with a default password.', 'info')

            else: # Update existing user's focal role info
                user.role = data['role_type'].lower() + '_focal'
                user.lga_id = data['lga_id']
                user.organization = data.get('organization')

            db.session.commit()
            return jsonify({'success': True, 'focal_person': user.to_dict()})

        # GET request logic
        users = User.query.filter(User.role.in_(['algon_focal', 'dcr_focal'])).all()
        return jsonify([user.to_dict() for user in users])
        
    @app.route('/api/lgas/<int:state_id>')
    @login_required
    def get_lgas_for_state(state_id):
        lgas = LGA.query.filter_by(state_id=state_id).all()
        return jsonify([{'id': lga.id, 'name': lga.name} for lga in lgas])

    @app.route('/api/device/<int:device_id>')
    @login_required
    def get_device_details(device_id):
        device = Device.query.get_or_404(device_id)
        # Add security check if needed, e.g., user can only see devices in their state
        return jsonify(device.to_dict())

    # Clear Data Routes
    @app.route('/admin/clear_data/<data_type>', methods=['POST'])
    @login_required
    @role_required('super_admin')
    def clear_data(data_type):
        try:
            if data_type == 'devices':
                Device.query.delete()
                message = 'All device data cleared successfully'
            elif data_type == 'focal_persons':
                FocalPerson.query.delete()
                message = 'All focal person data cleared successfully'
            elif data_type == 'wards':
                Ward.query.delete()
                message = 'All ward data cleared successfully'
            elif data_type == 'lgas':
                LGA.query.delete()
                message = 'All LGA data cleared successfully'
            elif data_type == 'states':
                State.query.delete()
                message = 'All state data cleared successfully'
            elif data_type == 'users':
                # Don't delete the current super admin user
                User.query.filter(User.id != current_user.id).delete()
                message = 'All user data cleared successfully (except current user)'
            else:
                return jsonify({'success': False, 'error': 'Invalid data type'}), 400
            
            db.session.commit()
            flash(message, 'success')
            return jsonify({'success': True, 'message': message})
        except Exception as e:
            db.session.rollback()
            error_message = f'Error clearing {data_type}: {str(e)}'
            flash(error_message, 'error')
            return jsonify({'success': False, 'error': error_message}), 500

    def get_organization_logos():
        """Retrieve organization logos from database"""
        logos = {}
        logo_records = SystemLogo.query.all()
        
        for logo in logo_records:
            logos[logo.organization] = {
                'data': logo.logo_data,
                'content_type': logo.content_type,
                'filename': logo.logo_filename
            }
        
        return logos

    def create_modern_pdf_with_logos(title, content_func, filename_prefix="document"):
        """Create modern PDF with square organization logos"""
        buffer = BytesIO()
        # Set margins for better layout
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=A4,
            leftMargin=0.5*inch,
            rightMargin=0.5*inch,
            topMargin=0.5*inch,
            bottomMargin=0.5*inch
        )
        
        # Create modern styles
        styles = getSampleStyleSheet()
        
        # Custom styles for modern look
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            spaceAfter=30,
            alignment=1,  # Center alignment
            textColor=colors.HexColor('#1f2937'),
            fontName='Helvetica-Bold'
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#374151'),
            fontName='Helvetica-Bold'
        )
        
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            spaceBefore=5,
            spaceAfter=5,
            textColor=colors.HexColor('#4b5563'),
            fontName='Helvetica'
        )
        
        story = []
        
        # Add modern header with square logos
        logos = get_organization_logos()
        if logos:
            logo_images = []
            
            for org in ['NPC', 'ALGON', 'UNICEF']:
                if org in logos:
                    logo_buffer = BytesIO(logos[org]['data'])
                    try:
                        # Create square logos (1x1 inch)
                        img = Image(logo_buffer, width=1*inch, height=1*inch)
                        logo_images.append(img)
                    except:
                        # Fallback to text
                        logo_images.append(Paragraph(f"<b>{org}</b>", normal_style))
                else:
                    logo_images.append(Paragraph(f"<b>{org}</b>", normal_style))
            
            if logo_images:
                # Create table with proper spacing
                logo_table = Table([logo_images], colWidths=[2.5*inch, 2.5*inch, 2.5*inch])
                logo_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 30),
                    ('TOPPADDING', (0, 0), (-1, -1), 10),
                ]))
                story.append(logo_table)
        
        # Add separator line
        line = HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e5e7eb'))
        story.append(line)
        story.append(Spacer(1, 20))
        
        # Add title
        story.append(Paragraph(title, title_style))
        
        # Add content using the provided function
        content_func(story, {
            'title': title_style,
            'heading': heading_style,
            'normal': normal_style
        })
        
        # Build and return PDF
        doc.build(story)
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"{filename_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mimetype='application/pdf'
        )

    # PDF Report Routes
    @app.route('/admin/pdf/state_receipt/<int:state_id>')
    @login_required
    @role_required('super_admin', 'state_admin')
    def generate_state_receipt_pdf(state_id):
        # State admin can only generate PDFs for their state
        if current_user.role == 'state_admin' and state_id != current_user.state_id:
            flash('You can only generate PDFs for your assigned state.', 'error')
            return redirect(url_for('state_admin_dashboard'))
            
        state = State.query.get_or_404(state_id)
        devices = Device.query.filter_by(state_id=state_id).all()
        
        def add_content(story, styles):
            # Modern title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                spaceAfter=15,
                textColor=colors.HexColor('#2563eb'),
                alignment=1
            )
            story.append(Paragraph("STATE DEVICE RECEIPT & ACKNOWLEDGMENT FORM", title_style))
            story.append(Spacer(1, 25))
            
            # State header box
            header_style = ParagraphStyle(
                'HeaderStyle',
                parent=styles['Heading1'], 
                fontSize=16,
                textColor=colors.white,
                backColor=colors.HexColor('#1f2937'),
                padding=10,
                alignment=1
            )
            story.append(Paragraph(f"STATE: {state.name.upper()} | CODE: {state.code}", header_style))
            story.append(Spacer(1, 25))
            
            # Summary information section
            section_style = ParagraphStyle(
                'SectionStyle',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#1f2937'),
                spaceAfter=8,
                backColor=colors.HexColor('#f8fafc'),
                padding=6
            )
            story.append(Paragraph("SECTION A: DEVICE ALLOCATION SUMMARY", section_style))
            story.append(Spacer(1, 10))
            
            # Calculate device statistics
            total_devices = len(devices)
            unclaimed_count = len([d for d in devices if d.status == 'unclaimed'])
            claimed_count = len([d for d in devices if d.status == 'claimed'])
            distributed_count = len([d for d in devices if d.status == 'distributed'])
            lga_count = LGA.query.filter_by(state_id=state_id).count()
            
            summary_data = [
                ['Total Devices Allocated:', str(total_devices)],
                ['Total LGAs in State:', str(lga_count)],
                ['Devices Unclaimed:', str(unclaimed_count)],
                ['Devices Claimed:', str(claimed_count)],
                ['Devices Distributed:', str(distributed_count)],
                ['Receipt Generated Date:', datetime.now().strftime('%B %d, %Y')],
                ['Receipt Generated Time:', datetime.now().strftime('%I:%M %p')]
            ]
            
            summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
            summary_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 25))
            
            # LGA Distribution Breakdown
            story.append(Paragraph("SECTION B: LGA DISTRIBUTION BREAKDOWN", section_style))
            story.append(Spacer(1, 10))
            
            lgas = LGA.query.filter_by(state_id=state_id).all()
            if lgas:
                lga_headers = ['S/N', 'LGA Name', 'Total Devices', 'Unclaimed', 'Claimed', 'Distributed']
                lga_data = [lga_headers]
                
                for i, lga in enumerate(lgas, 1):
                    lga_devices = Device.query.filter_by(lga_id=lga.id).all()
                    lga_unclaimed = len([d for d in lga_devices if d.status == 'unclaimed'])
                    lga_claimed = len([d for d in lga_devices if d.status == 'claimed'])
                    lga_distributed = len([d for d in lga_devices if d.status == 'distributed'])
                    
                    lga_data.append([
                        str(i),
                        lga.name,
                        str(len(lga_devices)),
                        str(lga_unclaimed),
                        str(lga_claimed),
                        str(lga_distributed)
                    ])
                
                lga_table = Table(lga_data, colWidths=[0.4*inch, 2.2*inch, 1*inch, 0.8*inch, 0.8*inch, 0.8*inch])
                lga_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('ALIGN', (1, 1), (1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d1d5db')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#374151')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ]))
                story.append(lga_table)
            else:
                story.append(Paragraph("No LGAs found for this state.", styles['Normal']))
            
            story.append(Spacer(1, 30))
            
            # Device sampling table (first 15 devices)
            story.append(Paragraph("SECTION C: DEVICE SAMPLE LISTING (First 15 Devices)", section_style))
            story.append(Spacer(1, 10))
            
            if devices:
                device_headers = ['S/N', 'Serial Number', 'IMEI1', 'Status', 'Assigned LGA']
                device_data = [device_headers]
                
                # Show first 15 devices as sample
                sample_devices = devices[:15]
                for i, device in enumerate(sample_devices, 1):
                    lga_name = device.lga.name if device.lga else 'Unassigned'
                    device_data.append([
                        str(i),
                        device.serial_number or 'Pending',
                        device.imei1 or 'N/A',
                        device.status.replace('_', ' ').title(),
                        lga_name
                    ])
                
                device_table = Table(device_data, colWidths=[0.4*inch, 1.8*inch, 1.8*inch, 1*inch, 1*inch])
                device_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('ALIGN', (4, 1), (4, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d1d5db')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#374151')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(device_table)
                
                if len(devices) > 15:
                    note_style = ParagraphStyle(
                        'NoteStyle',
                        parent=styles['Normal'],
                        fontSize=9,
                        textColor=colors.HexColor('#6b7280'),
                        alignment=1,
                        spaceAfter=10
                    )
                    story.append(Spacer(1, 10))
                    story.append(Paragraph(f"Note: Showing first 15 devices of {len(devices)} total devices allocated to this state.", note_style))
            else:
                story.append(Paragraph("No devices allocated to this state.", styles['Normal']))
            
            story.append(Spacer(1, 30))
            
            # Signature section
            story.append(Paragraph("SECTION D: ACKNOWLEDGMENT & SIGNATURES", section_style))
            story.append(Spacer(1, 15))
            
            # State official signature
            state_sig_data = [
                ['STATE COORDINATOR SIGNATURE', 'DATE'],
                ['', ''],
                ['', ''],
                ['Print Name: ________________________', '_______________']
            ]
            
            state_sig_table = Table(state_sig_data, colWidths=[4*inch, 2*inch])
            state_sig_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#9ca3af')),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
                ('TOPPADDING', (0, 1), (-1, 2), 20),
                ('BOTTOMPADDING', (0, 1), (-1, 2), 5),
                ('TOPPADDING', (0, 3), (-1, 3), 8),
                ('BOTTOMPADDING', (0, 3), (-1, 3), 8),
            ]))
            story.append(state_sig_table)
            story.append(Spacer(1, 20))
            
            # Federal official signature
            federal_sig_data = [
                ['FEDERAL COORDINATOR SIGNATURE', 'DATE'],
                ['', ''],
                ['', ''],
                ['Print Name: ________________________', '_______________']
            ]
            
            federal_sig_table = Table(federal_sig_data, colWidths=[4*inch, 2*inch])
            federal_sig_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#9ca3af')),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
                ('TOPPADDING', (0, 1), (-1, 2), 20),
                ('BOTTOMPADDING', (0, 1), (-1, 2), 5),
                ('TOPPADDING', (0, 3), (-1, 3), 8),
                ('BOTTOMPADDING', (0, 3), (-1, 3), 8),
            ]))
            story.append(federal_sig_table)
            story.append(Spacer(1, 15))
            
            # Add disclaimer/notes
            disclaimer_style = ParagraphStyle(
                'Disclaimer',
                parent=styles['Normal'],
                fontSize=8,
                textColor=colors.HexColor('#6b7280'),
                alignment=1,
                spaceAfter=5
            )
            story.append(Paragraph("This document serves as official acknowledgment of device allocation and receipt under the VERXID program.", disclaimer_style))
            story.append(Paragraph("All devices listed are accountable and must be distributed according to program guidelines.", disclaimer_style))
        
        pdf_buffer = create_modern_pdf_with_logos(f"State Receipt - {state.name}", add_content)
        
        return app.response_class(
            pdf_buffer.getvalue(),
            mimetype='application/pdf',
            headers={"Content-Disposition": f"attachment; filename=state_receipt_{state.code}.pdf"}
        )
    
    # State Device Assignment Form
    @app.route('/admin/pdf/state_assignment/<int:state_id>')
    @login_required
    @role_required('super_admin', 'state_admin')
    def generate_state_assignment_pdf(state_id):
        # State admin can only generate PDFs for their state
        if current_user.role == 'state_admin' and state_id != current_user.state_id:
            flash('You can only generate PDFs for your assigned state.', 'error')
            return redirect(url_for('state_admin_dashboard'))
            
        state = State.query.get_or_404(state_id)
        lgas = LGA.query.filter_by(state_id=state_id).all()
        
        def add_content(story, styles):
            # Modern title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                spaceAfter=15,
                textColor=colors.HexColor('#2563eb'),
                alignment=1
            )
            story.append(Paragraph("STATE DEVICE ASSIGNMENT FORM", title_style))
            story.append(Spacer(1, 25))
            
            # State header box
            header_style = ParagraphStyle(
                'HeaderStyle',
                parent=styles['Heading1'], 
                fontSize=16,
                textColor=colors.white,
                backColor=colors.HexColor('#1f2937'),
                padding=10,
                alignment=1
            )
            story.append(Paragraph(f"STATE: {state.name.upper()} | ASSIGNMENT TO LOCAL GOVERNMENT AREAS", header_style))
            story.append(Spacer(1, 25))
            
            # Assignment information section
            section_style = ParagraphStyle(
                'SectionStyle',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#1f2937'),
                spaceAfter=8,
                backColor=colors.HexColor('#f8fafc'),
                padding=6
            )
            story.append(Paragraph("SECTION A: ASSIGNMENT SUMMARY", section_style))
            story.append(Spacer(1, 10))
            
            # Calculate totals
            total_devices = Device.query.filter_by(state_id=state_id).count()
            assigned_devices = Device.query.filter(Device.state_id == state_id, Device.lga_id.isnot(None)).count()
            unassigned_devices = total_devices - assigned_devices
            
            assignment_data = [
                ['Total Devices for State:', str(total_devices)],
                ['Devices Assigned to LGAs:', str(assigned_devices)],
                ['Devices Unassigned:', str(unassigned_devices)],
                ['Total LGAs in State:', str(len(lgas))],
                ['Assignment Date:', datetime.now().strftime('%B %d, %Y')],
                ['Assignment Time:', datetime.now().strftime('%I:%M %p')]
            ]
            
            assignment_table = Table(assignment_data, colWidths=[3*inch, 3*inch])
            assignment_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(assignment_table)
            story.append(Spacer(1, 25))
            
            # LGA Assignment Breakdown
            story.append(Paragraph("SECTION B: DEVICE ASSIGNMENT BY LGA", section_style))
            story.append(Spacer(1, 10))
            
            if lgas:
                lga_headers = ['S/N', 'LGA Name', 'Assigned Devices', 'ALGON Focal', 'DCR Focal', 'Assignment Status']
                lga_data = [lga_headers]
                
                for i, lga in enumerate(lgas, 1):
                    lga_devices = Device.query.filter_by(lga_id=lga.id).all()
                    algon_focal = User.query.filter_by(lga_id=lga.id, role='algon_focal').first()
                    dcr_focal = User.query.filter_by(lga_id=lga.id, role='dcr_focal').first()
                    
                    assignment_status = "Complete" if len(lga_devices) > 0 else "Pending"
                    if len(lga_devices) > 0 and not algon_focal:
                        assignment_status = "Partial - No ALGON Focal"
                    elif len(lga_devices) > 0 and not dcr_focal:
                        assignment_status = "Partial - No DCR Focal"
                    
                    lga_data.append([
                        str(i),
                        lga.name,
                        str(len(lga_devices)),
                        algon_focal.full_name if algon_focal else "Not Assigned",
                        dcr_focal.full_name if dcr_focal else "Not Assigned",
                        assignment_status
                    ])
                
                lga_table = Table(lga_data, colWidths=[0.3*inch, 1.6*inch, 0.8*inch, 1.3*inch, 1.3*inch, 0.7*inch])
                lga_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('ALIGN', (1, 1), (1, -1), 'LEFT'),
                    ('ALIGN', (3, 1), (4, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d1d5db')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#374151')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(lga_table)
            else:
                story.append(Paragraph("No LGAs found for this state.", styles['Normal']))
            
            story.append(Spacer(1, 30))
            
            # Assignment authorization section
            story.append(Paragraph("SECTION C: ASSIGNMENT AUTHORIZATION", section_style))
            story.append(Spacer(1, 15))
            
            # State coordinator signature
            state_coord_sig_data = [
                ['STATE COORDINATOR SIGNATURE', 'DATE'],
                ['', ''],
                ['', ''],
                ['Print Name: ________________________', '_______________']
            ]
            
            state_coord_sig_table = Table(state_coord_sig_data, colWidths=[4*inch, 2*inch])
            state_coord_sig_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#9ca3af')),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
                ('TOPPADDING', (0, 1), (-1, 2), 20),
                ('BOTTOMPADDING', (0, 1), (-1, 2), 5),
                ('TOPPADDING', (0, 3), (-1, 3), 8),
                ('BOTTOMPADDING', (0, 3), (-1, 3), 8),
            ]))
            story.append(state_coord_sig_table)
            story.append(Spacer(1, 20))
            
            # Program director signature
            director_sig_data = [
                ['PROGRAM DIRECTOR SIGNATURE', 'DATE'],
                ['', ''],
                ['', ''],
                ['Print Name: ________________________', '_______________']
            ]
            
            director_sig_table = Table(director_sig_data, colWidths=[4*inch, 2*inch])
            director_sig_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#9ca3af')),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
                ('TOPPADDING', (0, 1), (-1, 2), 20),
                ('BOTTOMPADDING', (0, 1), (-1, 2), 5),
                ('TOPPADDING', (0, 3), (-1, 3), 8),
                ('BOTTOMPADDING', (0, 3), (-1, 3), 8),
            ]))
            story.append(director_sig_table)
            story.append(Spacer(1, 15))
            
            # Add disclaimer/notes
            disclaimer_style = ParagraphStyle(
                'Disclaimer',
                parent=styles['Normal'],
                fontSize=8,
                textColor=colors.HexColor('#6b7280'),
                alignment=1,
                spaceAfter=5
            )
            story.append(Paragraph("This document authorizes the assignment of devices to designated LGAs under the VERXID program.", disclaimer_style))
            story.append(Paragraph("All assigned focal persons are responsible for proper device distribution and accountability.", disclaimer_style))
            
        pdf_buffer = create_modern_pdf_with_logos(f"State Assignment - {state.name}", add_content)
        
        return app.response_class(
            pdf_buffer.getvalue(),
            mimetype='application/pdf',
            headers={"Content-Disposition": f"attachment; filename=state_assignment_{state.code}.pdf"}
        )

    @app.route('/admin/pdf/lga_distribution/<int:lga_id>')
    @login_required
    @role_required('super_admin', 'state_admin', 'algon_focal')
    def generate_lga_distribution_pdf(lga_id):
        lga = LGA.query.get_or_404(lga_id)
        
        # State admin can only generate PDFs for LGAs in their state
        if current_user.role == 'state_admin' and lga.state_id != current_user.state_id:
            flash('You can only generate PDFs for LGAs in your assigned state.', 'error')
            return redirect(url_for('state_admin_dashboard'))
            
        # ALGON focal can only generate PDFs for their assigned LGA
        if current_user.role == 'algon_focal' and lga.id != current_user.lga_id:
            flash('You can only generate PDFs for your assigned LGA.', 'error')
            return redirect(url_for('algon_dashboard'))
            
        devices = Device.query.filter_by(lga_id=lga_id, status='distributed').all()
        algon_focal = User.query.filter_by(lga_id=lga_id, role='algon_focal').first()
        dcr_focal = User.query.filter_by(lga_id=lga_id, role='dcr_focal').first()
        
        # Get LGA Chairman info (assuming it's stored in the system)
        lga_chairman = User.query.filter_by(lga_id=lga_id, role='lga_chairman').first() 
        
        def add_content(story, styles):
            # Header with LGA Chairman info
            if lga_chairman:
                story.append(Paragraph(f"<b>LGA CHAIRMAN:</b> {lga_chairman.full_name}", styles['Heading2']))
            else:
                story.append(Paragraph("<b>LGA CHAIRMAN:</b> ________________________", styles['Heading2']))
                
            story.append(Spacer(1, 10))
            
            if algon_focal:
                story.append(Paragraph(f"<b>ALGON FOCAL PERSON:</b> {algon_focal.full_name}", styles['Heading2']))
            else:
                story.append(Paragraph("<b>ALGON FOCAL PERSON:</b> ________________________", styles['Heading2']))
                
            story.append(Spacer(1, 20))
            
            # LGA Information
            info_data = [
                ['LGA:', lga.name, 'State:', lga.state.name],
                ['Total Distributed Devices:', str(len(devices)), 'Date:', datetime.now().strftime('%B %d, %Y')]
            ]
            
            info_table = Table(info_data, colWidths=[1.5*inch, 2*inch, 1*inch, 2*inch])
            info_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(info_table)
            story.append(Spacer(1, 30))
            
            # Device Cards (2 per row as requested)
            if devices:
                story.append(Paragraph("<b>DEVICE DISTRIBUTION DETAILS</b>", styles['Heading2']))
                story.append(Spacer(1, 15))
                
                # Create device cards, 2 per row
                for i in range(0, len(devices), 2):
                    row_devices = devices[i:i+2]
                    card_data = []
                    
                    for device in row_devices:
                        card_content = [
                            f"<b>S/N:</b> {device.serial_number or 'Pending'}",
                            f"<b>IMEI1:</b> {device.imei1 or 'N/A'}",
                            f"<b>IMEI2:</b> {device.imei2 or 'N/A'}",
                            "",
                            f"<b>RECIPIENT:</b>",
                            f"Name: {device.recipient_name or 'Unknown'}",
                            f"Designation: {device.recipient_designation or 'N/A'}",
                            f"Phone: {device.recipient_phone or 'N/A'}",
                            f"Center: {device.registration_center or 'N/A'}",
                            "",
                            f"<b>Recipient Signature:</b>",
                            "_________________________",
                            f"Date: {device.distributed_at.strftime('%d/%m/%Y') if device.distributed_at else 'N/A'}"
                        ]
                        
                        card_paragraph = Paragraph("<br/>".join(card_content), styles['Normal'])
                        card_data.append(card_paragraph)
                    
                    # Fill empty cell if odd number of devices
                    if len(card_data) == 1:
                        card_data.append(Paragraph("", styles['Normal']))
                    
                    # Create table for this row of cards
                    card_table = Table([card_data], colWidths=[3.5*inch, 3.5*inch])
                    card_table.setStyle(TableStyle([
                        ('BORDER', (0, 0), (-1, -1), 1, colors.HexColor('#d1d5db')),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 10),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                        ('TOPPADDING', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f9fafb')),
                    ]))
                    
                    story.append(card_table)
                    story.append(Spacer(1, 15))
            
            # Signature section at bottom
            story.append(Spacer(1, 40))
            story.append(Paragraph("<b>SIGNATURES</b>", styles['Heading2']))
            story.append(Spacer(1, 20))
            
            # Signature table for ALGON and DCR focals
            sig_data = [
                ['ALGON FOCAL PERSON', 'DCR FOCAL PERSON'],
                ['', ''],
                ['_________________________', '_________________________'],
                [algon_focal.full_name if algon_focal else '', dcr_focal.full_name if dcr_focal else ''],
                [f'Date: ________________', 'Date: ________________']
            ]
            
            sig_table = Table(sig_data, colWidths=[3.5*inch, 3.5*inch])
            sig_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 1), (-1, 1), 30),
                ('BOTTOMPADDING', (2, 0), (-1, -1), 10),
            ]))
            story.append(sig_table)
        
        return create_modern_pdf_with_logos(f"LGA Distribution Report - {lga.name}", add_content, f"lga_distribution_{lga.name}")

    # Individual Device Issuance Form PDF
    @app.route('/focal/pdf/device_issuance/<int:device_id>')
    @login_required
    @role_required('algon_focal', 'dcr_focal')
    def generate_device_issuance_pdf(device_id):
        device = Device.query.get_or_404(device_id)
        
        # Check permissions
        if current_user.role == 'algon_focal' and device.assigned_focal_id != current_user.id:
            flash('You can only generate PDFs for devices assigned to you.', 'error')
            return redirect(url_for('algon_dashboard'))
        
        # Get issuance form data if exists
        issuance_form = None
        if hasattr(device, 'verxid_issuance_form'):
            issuance_form = device.verxid_issuance_form
            
        def add_content(story, styles):
            # Modern title with better styling
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=22,
                spaceAfter=10,
                textColor=colors.HexColor('#2563eb'),
                alignment=1
            )
            story.append(Paragraph("DIGITAL DEVICE ISSUANCE & ACKNOWLEDGEMENT FORM", title_style))
            story.append(Spacer(1, 25))
            
            # Device header in a colored box
            header_style = ParagraphStyle(
                'HeaderStyle',
                parent=styles['Heading1'], 
                fontSize=14,
                textColor=colors.white,
                backColor=colors.HexColor('#1f2937'),
                padding=8,
                alignment=1
            )
            story.append(Paragraph(f"Device S/N: {device.serial_number or 'Pending Assignment'} | VERXID Registration Device", header_style))
            story.append(Spacer(1, 25))
            
            # Section A: Device Information with modern styling
            section_style = ParagraphStyle(
                'SectionStyle',
                parent=styles['Heading2'],
                fontSize=13,
                textColor=colors.HexColor('#1f2937'),
                spaceAfter=8,
                backColor=colors.HexColor('#f8fafc'),
                padding=6
            )
            story.append(Paragraph("SECTION A: DEVICE INFORMATION", section_style))
            story.append(Spacer(1, 10))
            
            device_data = [
                ['Device Type:', 'VERXID Digital Registration Device'],
                ['Device Make/Model:', device.model or 'VERXID Standard Tablet'],
                ['Serial Number:', device.serial_number or 'Pending Assignment'],
                ['IMEI 1:', device.imei1 or 'Not Available'],
                ['IMEI 2:', device.imei2 or 'Not Available'],
                ['Device Condition:', device.device_condition or 'Good (New)'],
                ['Deployment Status:', device.status.replace('_', ' ').title()]
            ]
            
            device_table = Table(device_data, colWidths=[2.2*inch, 3.8*inch])
            device_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ]))
            story.append(device_table)
            story.append(Spacer(1, 25))
            
            # Section B: Recipient Information
            if device.status == 'distributed':
                story.append(Paragraph("SECTION B: RECIPIENT INFORMATION", section_style))
                story.append(Spacer(1, 10))
                
                recipient_data = [
                    ['Full Name:', device.recipient_name or 'Not Provided'],
                    ['Official Designation:', device.recipient_designation or 'Not Specified'],
                    ['Staff ID Number:', device.staff_id or 'Not Provided'],
                    ['Registration Center:', device.registration_center_name or 'Not Assigned'],
                    ['Center Address:', device.registration_center_address or 'Not Provided'],
                    ['Phone Number:', device.recipient_phone or 'Not Provided'],
                    ['Email Address:', device.recipient_email or 'Not Provided'],
                    ['LGA Assignment:', device.lga.name if device.lga else 'Not Assigned'],
                    ['State Location:', device.state.name if device.state else 'Not Assigned']
                ]
                
                recipient_table = Table(recipient_data, colWidths=[2.2*inch, 3.8*inch])
                recipient_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                    ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ]))
                story.append(recipient_table)
                story.append(Spacer(1, 25))
                
                # Section C: Issuing Authority
                story.append(Paragraph("SECTION C: ISSUING AUTHORITY INFORMATION", section_style))
                story.append(Spacer(1, 10))
                
                focal_person = User.query.get(device.assigned_focal_id) if device.assigned_focal_id else None
                issuer_data = [
                    ['Authorized Officer:', focal_person.full_name if focal_person else 'Not Assigned'],
                    ['Official Title:', 'ALGON Focal Person'],
                    ['Office/Location:', f"{device.lga.name if device.lga else 'N/A'}, {device.state.name if device.state else 'N/A'}"],
                    ['Contact Information:', focal_person.phone if focal_person else 'Not Available'],
                    ['Date of Issuance:', device.distributed_at.strftime('%B %d, %Y') if device.distributed_at else 'Pending Distribution']
                ]
                
                issuer_table = Table(issuer_data, colWidths=[2.2*inch, 3.8*inch])
                issuer_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                    ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ]))
                story.append(issuer_table)
                story.append(Spacer(1, 30))
                
                # Modern signature section
                story.append(Paragraph("SECTION D: DIGITAL SIGNATURES & ACKNOWLEDGEMENT", section_style))
                story.append(Spacer(1, 15))
                
                # Recipient signature box
                sig_data = [
                    ['RECIPIENT SIGNATURE', 'DATE'],
                    ['', ''],
                    ['', ''],
                    [f"Print Name: {device.recipient_name or '________________________'}", '_______________']
                ]
                
                sig_table = Table(sig_data, colWidths=[4*inch, 2*inch])
                sig_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#9ca3af')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
                    ('TOPPADDING', (0, 1), (-1, 2), 20),
                    ('BOTTOMPADDING', (0, 1), (-1, 2), 5),
                    ('TOPPADDING', (0, 3), (-1, 3), 8),
                    ('BOTTOMPADDING', (0, 3), (-1, 3), 8),
                ]))
                story.append(sig_table)
                story.append(Spacer(1, 20))
                
                # Issuer signature
                issuer_sig_data = [
                    ['ISSUING OFFICER SIGNATURE', 'DATE'],
                    ['', ''],
                    ['', ''],
                    [f"Print Name: {focal_person.full_name if focal_person else '________________________'}", '_______________']
                ]
                
                issuer_sig_table = Table(issuer_sig_data, colWidths=[4*inch, 2*inch])
                issuer_sig_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#9ca3af')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
                    ('TOPPADDING', (0, 1), (-1, 2), 20),
                    ('BOTTOMPADDING', (0, 1), (-1, 2), 5),
                    ('TOPPADDING', (0, 3), (-1, 3), 8),
                    ('BOTTOMPADDING', (0, 3), (-1, 3), 8),
                ]))
                story.append(issuer_sig_table)
                story.append(Spacer(1, 20))
                
                # Witness signature (for DCR witness)
                witness_sig_data = [
                    ['WITNESS SIGNATURE (DCR FOCAL)', 'DATE'],
                    ['', ''],
                    ['', ''],
                    ['Print Name: ________________________', '_______________']
                ]
                
                witness_sig_table = Table(witness_sig_data, colWidths=[4*inch, 2*inch])
                witness_sig_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#9ca3af')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
                    ('TOPPADDING', (0, 1), (-1, 2), 20),
                    ('BOTTOMPADDING', (0, 1), (-1, 2), 5),
                    ('TOPPADDING', (0, 3), (-1, 3), 8),
                    ('BOTTOMPADDING', (0, 3), (-1, 3), 8),
                ]))
                story.append(witness_sig_table)
                story.append(Spacer(1, 15))
                
                # Add disclaimer/notes
                disclaimer_style = ParagraphStyle(
                    'Disclaimer',
                    parent=styles['Normal'],
                    fontSize=8,
                    textColor=colors.HexColor('#6b7280'),
                    alignment=1,
                    spaceAfter=5
                )
                story.append(Paragraph("This document serves as official proof of device issuance under the VERXID program.", disclaimer_style))
                story.append(Paragraph("For verification purposes, please retain this document and contact the issuing authority if needed.", disclaimer_style))
            
        pdf_buffer = create_modern_pdf_with_logos(f"Device Issuance Form - {device.serial_number or device.imei1}", add_content)
        
        return app.response_class(
            pdf_buffer.getvalue(),
            mimetype='application/pdf',
            headers={"Content-Disposition": f"attachment; filename=device_issuance_{device.serial_number or device.imei1}.pdf"}
        )

    # State-wide Summary PDF
    @app.route('/admin/pdf/state_summary/<int:state_id>')
    @login_required
    @role_required('super_admin', 'state_admin')
    def generate_state_summary_pdf(state_id):
        if current_user.role == 'state_admin' and state_id != current_user.state_id:
            flash('You can only generate PDFs for your assigned state.', 'error')
            return redirect(url_for('state_admin_dashboard'))
            
        state = State.query.get_or_404(state_id)
        lgas = LGA.query.filter_by(state_id=state_id).all()
        total_devices = Device.query.filter_by(state_id=state_id).count()
        
        def add_content(story, styles):
            story.append(Paragraph(f"<b>State-wide Device Distribution Summary</b>", styles['Title']))
            story.append(Paragraph(f"<b>State: {state.name}</b>", styles['Heading1']))
            story.append(Spacer(1, 20))
            
            # Total devices summary
            story.append(Paragraph(f"<b>Total Devices: {total_devices}</b>", styles['Heading2']))
            story.append(Spacer(1, 20))
            
            # LGA breakdown
            story.append(Paragraph("<b>LGA Distribution Breakdown</b>", styles['Heading2']))
            
            for lga in lgas:
                devices = Device.query.filter_by(lga_id=lga.id).all()
                focal_persons = User.query.filter_by(lga_id=lga.id, role='algon_focal').all()
                dcr_persons = User.query.filter_by(lga_id=lga.id, role='dcr_focal').all()
                
                lga_data = [
                    ['LGA Name:', lga.name],
                    ['Total Devices:', str(len(devices))],
                    ['Unclaimed:', str(len([d for d in devices if d.status == 'unclaimed']))],
                    ['Claimed:', str(len([d for d in devices if d.status == 'claimed']))],
                    ['Distributed:', str(len([d for d in devices if d.status == 'distributed']))],
                    ['ALGON Focal:', focal_persons[0].full_name if focal_persons else 'Not assigned'],
                    ['DCR Focal:', dcr_persons[0].full_name if dcr_persons else 'Not assigned']
                ]
                
                lga_table = Table(lga_data, colWidths=[2*inch, 4*inch])
                lga_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ]))
                story.append(lga_table)
                story.append(Spacer(1, 15))
            
        pdf_buffer = create_modern_pdf_with_logos(f"State Summary - {state.name}", add_content)
        
        return app.response_class(
            pdf_buffer.getvalue(),
            mimetype='application/pdf',
            headers={"Content-Disposition": f"attachment; filename=state_summary_{state.name.replace(' ', '_')}.pdf"}
        )

    # Comprehensive Distribution Report (All LGAs)
    @app.route('/admin/pdf/comprehensive_distribution/<int:state_id>')
    @login_required
    @role_required('super_admin', 'state_admin')
    def generate_comprehensive_distribution_pdf(state_id):
        if current_user.role == 'state_admin' and state_id != current_user.state_id:
            flash('You can only generate PDFs for your assigned state.', 'error')
            return redirect(url_for('state_admin_dashboard'))
            
        state = State.query.get_or_404(state_id)
        lgas = LGA.query.filter_by(state_id=state_id).all()
        
        def add_content(story, styles):
            # Modern title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                spaceAfter=15,
                textColor=colors.HexColor('#2563eb'),
                alignment=1
            )
            story.append(Paragraph("STATEWIDE DEVICE DISTRIBUTION LISTING", title_style))
            story.append(Spacer(1, 20))
            
            # State header box
            header_style = ParagraphStyle(
                'HeaderStyle',
                parent=styles['Heading1'], 
                fontSize=16,
                textColor=colors.white,
                backColor=colors.HexColor('#1f2937'),
                padding=10,
                alignment=1
            )
            story.append(Paragraph(f"STATE: {state.name.upper()} | COMPREHENSIVE LGA BREAKDOWN", header_style))
            story.append(Spacer(1, 25))
            
            # Section styling
            section_style = ParagraphStyle(
                'SectionStyle',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#1f2937'),
                spaceAfter=8,
                backColor=colors.HexColor('#f8fafc'),
                padding=6
            )
            
            for lga in lgas:
                # Start each LGA on a new page
                if lga != lgas[0]:
                    story.append(PageBreak())
                
                # LGA header
                lga_header_style = ParagraphStyle(
                    'LGAHeaderStyle',
                    parent=styles['Heading2'],
                    fontSize=15,
                    textColor=colors.white,
                    backColor=colors.HexColor('#374151'),
                    padding=8,
                    alignment=1
                )
                story.append(Paragraph(f"LGA: {lga.name.upper()}", lga_header_style))
                story.append(Spacer(1, 15))
                
                devices = Device.query.filter_by(lga_id=lga.id, status='distributed').all()
                focal_persons = User.query.filter_by(lga_id=lga.id, role='algon_focal').all()
                dcr_persons = User.query.filter_by(lga_id=lga.id, role='dcr_focal').all()
                
                # LGA Information with modern styling
                story.append(Paragraph("LGA PERSONNEL & SUMMARY", section_style))
                story.append(Spacer(1, 10))
                
                lga_info = [
                    ['ALGON Focal Person:', focal_persons[0].full_name if focal_persons else 'Not Assigned'],
                    ['Focal Contact Number:', focal_persons[0].phone if focal_persons else 'Not Available'],
                    ['DCR Focal Person:', dcr_persons[0].full_name if dcr_persons else 'Not Assigned'],
                    ['DCR Contact Number:', dcr_persons[0].phone if dcr_persons and dcr_persons[0].phone else 'Not Available'],
                    ['Total Devices Distributed:', str(len(devices))],
                    ['Distribution Status:', 'Active' if len(devices) > 0 else 'Pending']
                ]
                
                info_table = Table(lga_info, colWidths=[2.5*inch, 3.5*inch])
                info_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                    ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ]))
                story.append(info_table)
                story.append(Spacer(1, 20))
                
                # Device details
                if devices:
                    story.append(Paragraph("DISTRIBUTED DEVICES LISTING", section_style))
                    story.append(Spacer(1, 10))
                    
                    device_headers = ['S/N', 'Serial Number', 'IMEI1', 'Recipient Name', 'Distribution Date', 'Status']
                    device_data = [device_headers]
                    
                    for i, device in enumerate(devices, 1):
                        device_data.append([
                            str(i),
                            device.serial_number or 'Pending',
                            device.imei1 or 'N/A',
                            device.recipient_name or 'N/A',
                            device.distributed_at.strftime('%d/%m/%Y') if device.distributed_at else 'N/A',
                            'Distributed'
                        ])
                    
                    device_table = Table(device_data, colWidths=[0.4*inch, 1.2*inch, 1.2*inch, 1.7*inch, 1*inch, 0.5*inch])
                    device_table.setStyle(TableStyle([
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('ALIGN', (3, 1), (3, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d1d5db')),
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#374151')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                        ('LEFTPADDING', (0, 0), (-1, -1), 6),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ]))
                    story.append(device_table)
                else:
                    story.append(Paragraph("DISTRIBUTED DEVICES LISTING", section_style))
                    story.append(Spacer(1, 10))
                    story.append(Paragraph("No devices distributed in this LGA yet.", styles['Normal']))
                
                # Add LGA-level signatures for each LGA
                story.append(Spacer(1, 25))
                story.append(Paragraph("LGA ACKNOWLEDGMENT & SIGNATURES", section_style))
                story.append(Spacer(1, 15))
                
                # ALGON focal signature
                algon_sig_data = [
                    ['ALGON FOCAL SIGNATURE', 'DATE'],
                    ['', ''],
                    ['', ''],
                    [f"Print Name: {focal_persons[0].full_name if focal_persons else '________________________'}", '_______________']
                ]
                
                algon_sig_table = Table(algon_sig_data, colWidths=[3.5*inch, 2.5*inch])
                algon_sig_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#9ca3af')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
                    ('TOPPADDING', (0, 1), (-1, 2), 15),
                    ('BOTTOMPADDING', (0, 1), (-1, 2), 5),
                    ('TOPPADDING', (0, 3), (-1, 3), 8),
                    ('BOTTOMPADDING', (0, 3), (-1, 3), 8),
                ]))
                story.append(algon_sig_table)
                story.append(Spacer(1, 15))
                
                # DCR focal signature
                dcr_sig_data = [
                    ['DCR FOCAL SIGNATURE', 'DATE'],
                    ['', ''],
                    ['', ''],
                    [f"Print Name: {dcr_persons[0].full_name if dcr_persons else '________________________'}", '_______________']
                ]
                
                dcr_sig_table = Table(dcr_sig_data, colWidths=[3.5*inch, 2.5*inch])
                dcr_sig_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#9ca3af')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
                    ('TOPPADDING', (0, 1), (-1, 2), 15),
                    ('BOTTOMPADDING', (0, 1), (-1, 2), 5),
                    ('TOPPADDING', (0, 3), (-1, 3), 8),
                    ('BOTTOMPADDING', (0, 3), (-1, 3), 8),
                ]))
                story.append(dcr_sig_table)
                story.append(Spacer(1, 20))
            
            # State-level summary and signatures at the end
            story.append(PageBreak())
            story.append(Paragraph("STATEWIDE DISTRIBUTION SUMMARY & AUTHORIZATION", section_style))
            story.append(Spacer(1, 15))
            
            # Calculate state totals
            total_state_devices = Device.query.filter_by(state_id=state_id).count()
            total_distributed = Device.query.filter_by(state_id=state_id, status='distributed').count()
            total_lgas_active = len([lga for lga in lgas if Device.query.filter_by(lga_id=lga.id, status='distributed').count() > 0])
            
            state_summary_data = [
                ['Total Devices Allocated to State:', str(total_state_devices)],
                ['Total Devices Distributed:', str(total_distributed)],
                ['Total LGAs with Active Distribution:', f"{total_lgas_active} out of {len(lgas)}"],
                ['Distribution Completion Rate:', f"{(total_distributed/total_state_devices*100):.1f}%" if total_state_devices > 0 else "0%"],
                ['Report Generated On:', datetime.now().strftime('%B %d, %Y at %I:%M %p')]
            ]
            
            state_summary_table = Table(state_summary_data, colWidths=[3.5*inch, 2.5*inch])
            state_summary_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(state_summary_table)
            story.append(Spacer(1, 30))
            
            # State-level signatures
            story.append(Paragraph("STATE LEVEL AUTHORIZATION SIGNATURES", section_style))
            story.append(Spacer(1, 15))
            
            # State coordinator signature
            state_coord_sig_data = [
                ['STATE COORDINATOR SIGNATURE', 'DATE'],
                ['', ''],
                ['', ''],
                ['Print Name: ________________________', '_______________']
            ]
            
            state_coord_sig_table = Table(state_coord_sig_data, colWidths=[4*inch, 2*inch])
            state_coord_sig_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#9ca3af')),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
                ('TOPPADDING', (0, 1), (-1, 2), 20),
                ('BOTTOMPADDING', (0, 1), (-1, 2), 5),
                ('TOPPADDING', (0, 3), (-1, 3), 8),
                ('BOTTOMPADDING', (0, 3), (-1, 3), 8),
            ]))
            story.append(state_coord_sig_table)
            story.append(Spacer(1, 20))
            
            # Program director signature
            program_director_sig_data = [
                ['PROGRAM DIRECTOR SIGNATURE', 'DATE'],
                ['', ''],
                ['', ''],
                ['Print Name: ________________________', '_______________']
            ]
            
            program_director_sig_table = Table(program_director_sig_data, colWidths=[4*inch, 2*inch])
            program_director_sig_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#9ca3af')),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
                ('TOPPADDING', (0, 1), (-1, 2), 20),
                ('BOTTOMPADDING', (0, 1), (-1, 2), 5),
                ('TOPPADDING', (0, 3), (-1, 3), 8),
                ('BOTTOMPADDING', (0, 3), (-1, 3), 8),
            ]))
            story.append(program_director_sig_table)
            story.append(Spacer(1, 15))
            
            # Add disclaimer/notes
            disclaimer_style = ParagraphStyle(
                'Disclaimer',
                parent=styles['Normal'],
                fontSize=8,
                textColor=colors.HexColor('#6b7280'),
                alignment=1,
                spaceAfter=5
            )
            story.append(Paragraph("This comprehensive listing provides a complete overview of device distribution across all LGAs in the state.", disclaimer_style))
            story.append(Paragraph("All listed devices are accountable and subject to regular monitoring and evaluation procedures.", disclaimer_style))
            
        pdf_buffer = create_modern_pdf_with_logos(f"Comprehensive Distribution - {state.name}", add_content)
        
        return app.response_class(
            pdf_buffer.getvalue(),
            mimetype='application/pdf',
            headers={"Content-Disposition": f"attachment; filename=comprehensive_distribution_{state.name.replace(' ', '_')}.pdf"}
        )

    # Signature Upload and Management Routes
    @app.route('/upload_signature')
    @login_required
    def upload_signature_page():
        return render_template('upload_signature.html')

    @app.route('/api/upload_signature', methods=['POST'])
    @login_required
    def api_upload_signature():
        try:
            if 'signature' not in request.files:
                return jsonify({'error': 'No signature file provided'}), 400
            
            file = request.files['signature']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            # Validate file type
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
            if not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
                return jsonify({'error': 'Invalid file type. Please upload PNG, JPG, JPEG, or GIF files only.'}), 400
            
            # Read and encode the file
            file_data = file.read()
            
            # Validate file size (max 2MB)
            if len(file_data) > 2 * 1024 * 1024:
                return jsonify({'error': 'File too large. Maximum size is 2MB.'}), 400
            
            # Encode to base64
            import base64
            signature_data = base64.b64encode(file_data).decode('utf-8')
            
            # Save to user's profile
            current_user.signature_data = signature_data
            current_user.signature_filename = file.filename
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Signature uploaded successfully',
                'signature_data': signature_data
            })
            
        except Exception as e:
            return jsonify({'error': f'Upload failed: {str(e)}'}), 500

    @app.route('/api/get_user_signature')
    @login_required  
    def api_get_user_signature():
        try:
            if current_user.signature_data:
                return jsonify({
                    'success': True,
                    'signature_data': current_user.signature_data,
                    'filename': getattr(current_user, 'signature_filename', 'signature.png')
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'No signature found'
                })
        except Exception as e:
            return jsonify({'error': f'Failed to retrieve signature: {str(e)}'}), 500

    @app.route('/api/delete_signature', methods=['POST'])
    @login_required
    def api_delete_signature():
        try:
            current_user.signature_data = None
            current_user.signature_filename = None
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Signature deleted successfully'
            })
            
        except Exception as e:
            return jsonify({'error': f'Failed to delete signature: {str(e)}'}), 500