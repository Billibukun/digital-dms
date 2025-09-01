"""
WSGI file for PythonAnywhere deployment
VERXID Device Documentation Management System
"""

import sys
import os

# Add the path to your app directory
path = '/home/npcapps/dsm'  # Change this to your actual PythonAnywhere path
if path not in sys.path:
    sys.path.insert(0, path)

from app import create_app

# Create the application
application = create_app()

if __name__ == "__main__":
    application.run()