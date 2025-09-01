# VERXID Device Management System - PythonAnywhere Deployment Guide

## Prerequisites
- PythonAnywhere account (recommended: Hacker plan for MySQL database)
- Basic understanding of Python web applications

## Deployment Steps

### 1. Upload Files to PythonAnywhere
1. Compress your entire project folder (excluding __pycache__, logs, etc.)
2. Upload to PythonAnywhere using the Files tab
3. Extract in your home directory: `/home/yourusername/`

### 2. Set up Virtual Environment
```bash
mkvirtualenv --python=/usr/bin/python3.10 verxid-env
cd /home/yourusername/claude
pip install -r requirements.txt
```

### 3. Configure Database
#### Option A: SQLite (for testing)
- No additional configuration needed
- Database will be created automatically in `instance/` directory

#### Option B: MySQL (recommended for production)
1. Create a MySQL database in PythonAnywhere dashboard
2. Set environment variable or update `app.py`:
```python
# In app.py, update database_url:
database_url = 'mysql+pymysql://username:password@username.mysql.pythonanywhere-services.com/username$verxid'
```

### 4. Configure Web App
1. Go to Web tab in PythonAnywhere dashboard
2. Create new web app (Python 3.10, Manual configuration)
3. Set the following:
   - **Source code**: `/home/yourusername/claude`
   - **Working directory**: `/home/yourusername/claude`
   - **WSGI configuration file**: `/home/yourusername/claude/wsgi.py`
   - **Virtualenv**: `/home/yourusername/.virtualenvs/verxid-env`

### 5. Update WSGI File
Edit `/home/yourusername/claude/wsgi.py`:
```python
import sys
import os

# Update this path to your actual directory
path = '/home/yourusername/claude'
if path not in sys.path:
    sys.path.insert(0, path)

from app import create_app
application = create_app()
```

### 6. Set Environment Variables (Optional)
In the Web tab > Environment variables:
- `SECRET_KEY`: Your secure secret key
- `DATABASE_URL`: MySQL connection string (if using MySQL)

### 7. Static Files Configuration
In Web tab > Static files:
- URL: `/static/`
- Directory: `/home/yourusername/claude/static/`

### 8. Initialize Database
Open a Bash console in PythonAnywhere:
```bash
workon verxid-env
cd /home/yourusername/claude
python3 -c "from app import create_app; app = create_app(); app.app_context().push(); print('Database initialized')"
```

### 9. Test and Go Live
1. Click "Reload" button in Web tab
2. Visit your app at `https://yourusername.pythonanywhere.com`
3. Login with default credentials:
   - **Email**: `druid@druidapps.com`
   - **Password**: `@druid.app.test`

## Default Login Credentials
- **Super Admin**: 
  - Email: `druid@druidapps.com`
  - Password: `@druid.app.test`

## Important Security Notes
1. **Change default passwords** immediately after deployment
2. **Set a strong SECRET_KEY** in production
3. **Use MySQL database** for production (not SQLite)
4. **Regular database backups** are recommended

## Features Included
- ✅ User role management (Super Admin, State Admin, ALGON Focal, DCR Focal)
- ✅ Device distribution tracking
- ✅ PDF report generation with modern layouts
- ✅ Signature upload functionality
- ✅ CSV data import/export
- ✅ Barcode scanner integration
- ✅ State/LGA/Ward hierarchical management
- ✅ Responsive dashboard design
- ✅ Reports center with role-based access

## Troubleshooting

### Common Issues:
1. **Import errors**: Ensure all dependencies are installed in virtual environment
2. **Database errors**: Check database configuration and permissions
3. **Static files not loading**: Verify static files path configuration
4. **Permission errors**: Check file permissions in the upload directory

### Logs Location:
- Application logs: Check PythonAnywhere error logs in Web tab
- Custom logs: `/home/yourusername/claude/logs/`

## Support
For technical support or customization requests, contact the development team.

---
**VERXID Device Documentation Management System**  
*Developed for efficient device distribution and tracking*