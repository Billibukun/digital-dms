"""
Initialize the database schema and create initial admin user.
Run this script after creating the Cloud SQL instance.
"""
import os
from app import create_app, db
from models import User

def init_db():
    app = create_app()
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(email='admin@verxid.com').first()
        if not admin:
            admin = User(
                email='admin@verxid.com',
                password='changeme123',  # Change this in production!
                first_name='Admin',
                last_name='User',
                role='admin',
                is_active=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created with email: admin@verxid.com")
        
        print("Database initialization complete!")

if __name__ == '__main__':
    init_db()
