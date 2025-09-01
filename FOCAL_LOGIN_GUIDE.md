# Device Documentation Management System
## Focal Person Login Guide

### System Overview
The **Device Documentation Management System (DDMS)** is developed by **Data Druid Services** and implemented by **Ibukunoluwa Omonijo** for comprehensive device tracking and distribution management.

---

## How Focal Persons Login

### 1. **Account Creation**
Focal person accounts are created by system administrators through:
- CSV data import (recommended for bulk creation)
- Individual account creation by Super Admin or State Admin

### 2. **Default Login Credentials**
When accounts are created for focal persons:
- **Username**: Usually their email address (without @domain.com)
- **Email**: As provided in the focal data
- **Default Password**: `password123` (MUST be changed on first login)

### 3. **Login Process**
1. Navigate to the system URL: `http://localhost:5002` (or production URL)
2. Use your assigned email address and password
3. You will be redirected to your appropriate dashboard based on role

### 4. **User Roles and Access**

#### **ALGON Focal Person**
- **Role**: `algon_focal`
- **Access**: 
  - View and claim devices assigned to their LGA
  - Create distribution records
  - Access barcode scanner for device verification
  - Manage ward-level distributions

#### **DCR Focal Person** 
- **Role**: `dcr_focal`
- **Access**:
  - Witness device claims and distributions
  - Verify device handovers
  - Access distribution forms for witnessing

---

## Account Information Lookup

### If you don't know your login credentials:

1. **Contact your State Administrator** - They have access to user management
2. **Contact Super Administrator** - Full system access
3. **Check the CSV file** used for your account creation (if available)

### Account Recovery:
- Currently, password reset must be done by administrators
- Contact system administrators with:
  - Your full name
  - Phone number
  - LGA assignment
  - Role (ALGON or DCR)

---

## First-Time Login Steps

1. **Login with default credentials**
   ```
   Email: [your-provided-email]
   Password: password123
   ```

2. **Change Password** (Recommended)
   - Go to user profile settings
   - Update to a secure password

3. **Verify Your Information**
   - Confirm your LGA assignment is correct
   - Check your role permissions
   - Update contact information if needed

---

## Troubleshooting Common Issues

### **"Method Not Allowed" Error**
- Clear browser cache and cookies
- Try using a different browser
- Contact administrator if issue persists

### **"Access Denied" Error**
- Your account may not be activated
- Role permissions may need adjustment
- Contact your State Administrator

### **"Invalid Credentials" Error**
- Double-check email address (no typos)
- Ensure you're using the correct password
- Account may be inactive - contact administrator

### **Cannot Access Specific Features**
- Feature access depends on your role
- ALGON focals: Can claim and distribute devices
- DCR focals: Can witness distributions
- Contact administrator if you need additional permissions

---

## System Features by Role

### **ALGON Focal Features:**
- ✅ Dashboard with device statistics
- ✅ Device claiming interface
- ✅ Barcode scanner for device verification
- ✅ Distribution form creation
- ✅ Ward-level distribution management

### **DCR Focal Features:**
- ✅ Witness dashboard
- ✅ Distribution witnessing interface
- ✅ Device verification access
- ✅ Distribution form validation

---

## Support Information

### **Technical Support:**
- **Developer**: Ibukunoluwa Omonijo
- **Company**: Data Druid Services
- **System**: Device Documentation Management System

### **Administrative Support:**
- **Super Admin**: druid@druidapps.com
- **State Administrators**: Contact your state office

### **For Account Issues:**
1. Verify account information with your LGA coordinator
2. Contact state administrator for password resets
3. Report system bugs to technical support

---

## Security Best Practices

1. **Change Default Password**: Never use `password123` permanently
2. **Use Strong Passwords**: Include letters, numbers, and symbols
3. **Logout After Use**: Always logout when finished
4. **Don't Share Credentials**: Keep login information confidential
5. **Report Suspicious Activity**: Contact administrators immediately

---

## System Requirements

- **Browser**: Chrome, Firefox, Safari, or Edge (latest versions)
- **Internet**: Stable internet connection required
- **Mobile**: Responsive design works on tablets and phones
- **Camera**: Required for barcode scanning functionality

---

*This guide is for the Device Documentation Management System v1.0*  
*Last updated: August 2024*  
*© 2024 Data Druid Services | Implemented by Ibukunoluwa Omonijo*