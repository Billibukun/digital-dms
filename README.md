# VERXID Digital Device Management System

A comprehensive Flask-based web application for managing VERXID digital devices with multi-level user management, barcode scanning, device tracking, and digital signature capabilities.

## Features

### 🔐 Multi-Level User Management
- **Super Admin**: Complete system access across all states
- **State Admin**: Manage users and devices within assigned state
- **ALGON Focal**: Claim and distribute devices at LGA level
- **DCR Focal**: Witness device claims and distributions

### 📱 Device Lifecycle Management
- **Unclaimed → Claimed → Distributed** workflow
- Barcode scanning for bulk IMEI processing
- Serial number entry during claiming process
- Auto-assignment based on state/LGA codes

### ✍️ Digital Signature System
- Reusable signatures for focal persons
- Canvas-based signature capture (touch/mouse support)
- Multi-party signatures (ALGON, DCR, Recipients)

### 🔧 Comprehensive Interfaces
- **Barcode Scanner**: Camera-based scanning using ZXing library
- **Device Claiming**: ALGON focal persons claim unclaimed devices
- **DCR Witness Dashboard**: DCR focal persons witness ALGON claims
- **Data Management**: Manage states, LGAs, wards, and focal persons

### 📄 VERXID Issuance Form
- Complete digital form matching official VERXID structure
- Accessories tracking with quantities
- Comprehensive terms and conditions
- Multi-party digital signatures

### 📊 CSV Data Management
- Bulk device uploads with auto-assignment
- Focal persons import with role-based processing
- States, LGAs, and wards bulk import
- Template downloads and validation

### 📈 Reporting & Analytics
- Device status tracking and analytics
- Distribution reports and audit trails
- PDF generation for official forms
- Search and filtering capabilities

## Technology Stack

- **Backend**: Flask, SQLAlchemy, Flask-Login
- **Frontend**: Bootstrap 5, HTML5 Canvas, JavaScript
- **Database**: SQLite (development), PostgreSQL/MySQL (production)
- **Barcode Scanning**: ZXing JavaScript Library
- **PDF Generation**: ReportLab (planned)
- **Authentication**: Flask-Login with role-based access control

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd device_app/claude
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database**
   ```bash
   python app.py
   ```
   The application will automatically create the SQLite database and default super admin account.

5. **Access the application**
   - Open browser to `http://localhost:5002`
   - Login with default credentials:
     - **Email**: `druid@druidapps.com`
     - **Password**: `@druid.app.test`

## Project Structure

```
claude/
├── app.py                          # Main Flask application
├── models.py                       # Database models
├── routes.py                       # Application routes and API endpoints
├── requirements.txt                # Python dependencies
├── README.md                       # This file
│
├── templates/                      # HTML templates
│   ├── base.html                  # Base template
│   ├── login.html                 # Login page
│   │
│   ├── admin/                     # Admin templates
│   │   ├── super_admin_dashboard.html
│   │   ├── state_admin_dashboard.html
│   │   ├── manage_users.html
│   │   ├── create_user.html
│   │   ├── manage_devices.html
│   │   ├── barcode_scanner.html
│   │   ├── csv_upload.html
│   │   └── data_management.html
│   │
│   └── focal/                     # Focal person templates
│       ├── algon_dashboard.html
│       ├── device_claiming.html
│       ├── dcr_dashboard.html
│       └── verxid_issuance_form.html
│
└── static/                        # Static files
    ├── css/
    │   └── style.css              # Custom styles
    ├── js/                        # JavaScript files
    ├── uploads/                   # File uploads
    ├── signatures/                # Signature storage
    └── logos/                     # Organization logos
```

## User Roles and Permissions

### Super Admin (`super_admin`)
- Manage all states, users, and devices
- Create state administrators
- Access to barcode scanner and CSV uploads
- Full data management capabilities
- Generate system-wide reports

### State Admin (`state_admin`)
- Manage users and devices within assigned state
- Create ALGON and DCR focal persons for their state
- Access to state-level barcode scanning and CSV uploads
- State-specific data management
- Generate state-level reports

### ALGON Focal (`algon_focal`)
- View assigned devices dashboard
- Claim unclaimed devices through testing and verification
- Issue devices using VERXID issuance form
- Digital signature for device claiming

### DCR Focal (`dcr_focal`)
- Witness device claims by ALGON focal persons
- Bulk witness capabilities
- Digital signature for witnessing
- View pending claims requiring witness

## Key Workflows

### Device Management Workflow
1. **Admin uploads devices** via CSV with state/LGA codes
2. **System auto-assigns** devices to ALGON focal persons based on location
3. **ALGON focal claims device** through comprehensive testing process
4. **DCR focal witnesses** the claim with digital signature
5. **ALGON focal issues device** using official VERXID form to recipient

### User Creation Workflow
1. **Super admin creates state admins** for each state
2. **State admins create focal persons** (ALGON and DCR) for their LGAs
3. **Focal persons receive login credentials** to access their dashboards
4. **System maintains role-based access** throughout all operations

### Data Import Workflow
1. **Download CSV templates** for the data type
2. **Populate template** with required information
3. **Upload CSV file** through admin interface
4. **System validates and processes** data automatically
5. **Review import results** and handle any errors

## CSV Templates

### Devices Template
```csv
serial_number,device_type,imei1,imei2,model,manufacturer,state_code,lga_code,carton_number,barcode
VRX001TAB,VERXID Tablet,123456789012345,123456789012346,Model-X,VERXID,NG,LGA001,CTN001,BC123
```

### Focal Persons Template
```csv
name,phone,email,lga_name,state_name,role_type,organization,witness_for
John Doe,08012345678,john@example.com,Abuja Municipal,FCT,ALGON,ALGON,
```

### States Template
```csv
name,code
Lagos State,LG
```

### LGAs Template
```csv
name,code,state_name,chairman_name,chairman_phone
Ikeja,IKJ,Lagos State,Chairman Name,08012345678
```

## API Endpoints

### Authentication
- `POST /login` - User login
- `GET /logout` - User logout

### Dashboard Routes
- `GET /dashboard` - Role-based dashboard redirect
- `GET /admin/super` - Super admin dashboard
- `GET /admin/state_admin_dashboard` - State admin dashboard
- `GET /focal/algon` - ALGON focal dashboard
- `GET /dcr/witness` - DCR witness dashboard

### Device Management
- `GET /admin/devices` - Manage devices interface
- `GET /admin/barcode_scanner` - Barcode scanning interface
- `POST /admin/process_barcode` - Process scanned barcodes
- `GET /focal/device_claiming/<int:device_id>` - Device claiming form
- `POST /focal/process_claim` - Submit device claim
- `GET /focal/issue_device/<int:device_id>` - VERXID issuance form
- `POST /focal/submit_issuance_form` - Submit issuance form

### Data Management API
- `GET /api/states` - Get all states
- `POST /api/states` - Create new state
- `GET /api/lgas` - Get LGAs (filtered by role)
- `POST /api/lgas` - Create new LGA
- `GET /api/wards` - Get wards (filtered by role)
- `POST /api/wards` - Create new ward
- `GET /api/focal_persons` - Get focal persons (filtered by role)
- `POST /api/focal_persons` - Create new focal person

### File Operations
- `GET /admin/csv_upload` - CSV upload interface
- `POST /admin/csv_upload` - Process CSV upload

## Security Features

- **Role-based access control** with proper authorization checks
- **Password hashing** using Werkzeug security
- **Session management** with Flask-Login
- **Input validation** and sanitization
- **CSRF protection** ready for production
- **File upload validation** with size and type restrictions

## Deployment

### Development
The application is configured to run on port 5002 in development mode:
```bash
python app.py
```

### Production Deployment

1. **Environment Variables**
   ```bash
   export FLASK_ENV=production
   export SECRET_KEY=your-production-secret-key
   export DATABASE_URL=postgresql://user:pass@host/dbname
   ```

2. **Database Migration**
   ```bash
   # For production, use PostgreSQL or MySQL
   # Update app.py with production database URL
   ```

3. **Web Server Configuration**
   ```bash
   # Using Gunicorn
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5002 app:app
   ```

4. **Reverse Proxy (Nginx)**
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://localhost:5002;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

## Browser Compatibility

- **Chrome 80+** (Recommended)
- **Firefox 75+**
- **Safari 13+**
- **Edge 80+**

**Note**: Camera-based barcode scanning requires HTTPS in production environments.

## Mobile Support

The application is fully responsive and supports:
- **Touch-based signatures** on mobile devices
- **Mobile camera access** for barcode scanning
- **Responsive layouts** for all screen sizes
- **Progressive Web App** capabilities ready

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Check the documentation for common solutions

## Changelog

### Version 1.0.0
- Initial release with complete VERXID system functionality
- Multi-level user management
- Device lifecycle management
- Digital signature system
- Barcode scanning capabilities
- CSV data import/export
- Comprehensive admin interfaces
- Mobile-responsive design

---

**Developed for VERXID Digital Device Management**  
*Comprehensive solution for device tracking, distribution, and management*