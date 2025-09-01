"""
WSGI configuration for VERXID Device Documentation Management System
Deployed on Google Cloud Run
"""

import os
from app import create_app

# Create the application
application = create_app()

if __name__ == "__main__":
    # This is used when running locally
    port = int(os.environ.get("PORT", 8080))
    application.run(host="0.0.0.0", port=port, debug=False)