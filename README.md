# User Login Monitoring System - Application Information
  - The user login monitoring agent is only for Windows
  - Web portal allows creating multiple companies and different sites - (api key) what you can devide monitoring users
  - allows global system management or per company user access
  - MFA login option included
  - Possible to allow register user account, if enabled
  - Limit registration to specific domains
  - 
    
## **Overview**
A login monitoring system built with Flask that tracks user authentication events across Windows domains. Features multi-tenancy support.
Windows monitoring agent:
https://github.com/ghostersk/winauthmon-agent

## **Website Overview**
![image](https://github.com/user-attachments/assets/e49dd1d8-0dbe-4c46-93ec-de0b86cd5ff6)
![image](https://github.com/user-attachments/assets/7666dc97-f936-4fcd-ac22-af7e80ba50e4)
![image](https://github.com/user-attachments/assets/aa5bdcd0-fb35-4e17-a81f-74f2c19e3249)
![image](https://github.com/user-attachments/assets/2fb90025-5259-42d2-971c-9f8e864ca8f3)
![image](https://github.com/user-attachments/assets/7b192870-20a6-417f-a115-8996db9d571f)
![image](https://github.com/user-attachments/assets/61c6e214-f1ff-45f2-92b0-b21501b338fe)
![image](https://github.com/user-attachments/assets/ca9c3abf-bb32-4054-a0a6-2911b4fa075f)
![image](https://github.com/user-attachments/assets/edb4b3d9-075d-455f-abf0-3770daba9638)


### **Core Components**
```
winauthmon-agent/
├── app.py                    # Main Flask application with Uvicorn ASGI server
├── extensions.py             # Flask extensions and configuration
├── config.ini               # Configuration file with multiple database support
├── requirements.txt          # Python dependencies
└── run.sh                   # Application startup script

├── auth/                   # Authentication & Authorization Module
│   ├── models.py           # User, Company, ApiKey, Settings models
│   ├── routes.py           # Auth routes (login, register, MFA, admin)
│   └── forms.py            # WTForms for validation

├── api/                     # REST API Module
│   ├── models.py           # Log, ErrorLog models
│   └── routes.py           # API endpoints (/log_event, /health)

├── frontend/                # Web Interface Module
│   ├── routes.py           # Dashboard, reports, home routes
│   └── models.py           # Frontend-specific models

├── utils/                   # Utility Modules
│   ├── security_headers.py  # Security headers middleware
│   ├── rate_limiter.py     # Rate limiting with Redis support
│   └── health_check.py     # System health monitoring

├── templates/              # Jinja2 Templates
│   ├── base.html          # Base template with dark theme
│   ├── auth/              # Authentication templates
│   └── frontend/          # Dashboard and report templates

├── static/                 # Static Assets
│   ├── css/               # Bootstrap 5, DataTables, custom CSS
│   ├── js/                # jQuery, DataTables, charts, custom JS
│   └── img/               # Icons and images

├── windows_agent/          # Windows Client
│   └── winagentUSM.exe    # Compiled Windows monitoring agent
         (compiled or downloaded from: https://github.com/ghostersk/winauthmon-agent)                            
└── instance/              # Instance-specific files
    ├── database.db        # SQLite database (default)
    └── certs/            # SSL certificates
```

### **Multi-Tenancy**
- **Company Isolation**: Complete data separation between organizations
- **Role-Based Access Control**: GlobalAdmin, Admin, CompanyAdmin, User roles
- **API Key Management**: Per-company API keys with usage tracking
- **User Assignment**: Users can belong to multiple companies

### **Authentication & Security**
- **Multi-Factor Authentication (MFA)**: TOTP with QR code setup
- **Flexible MFA Policies**: Global enforcement with per-user overrides
- **Password Policies**: Configurable strength requirements
- **Session Security**: Secure cookies, HTTPS enforcement
- **Rate Limiting**: Brute force protection

### **Monitoring & Logging**
- **Real-time Event Tracking**: Login, logout, lock events
- **Windows Agent Integration**: Automated event collection
- **API Health Monitoring**: Database connectivity checks
- **Error Logging**: Structured application error tracking
- **Audit Trail**: Complete user action logging

### **Dashboard & Reporting**
- **Interactive Dashboard**: Real-time login event monitoring
- **Column Visibility Controls**: Customizable table views with localStorage persistence
- **Time Spent Reports**: User session duration analysis
- **Export Capabilities**: CSV, Excel, PDF export
- **Date Range Filtering**: Flexible time period selection

### **Core Tables**
```sql
-- Authentication
app_auth_users              # User accounts with MFA
app_auth_companies          # Company/organization entities
app_auth_user_companies     # Many-to-many user-company relationships
app_auth_api_keys          # API keys with company association
app_auth_settings          # Global application settings

-- Logging
api_logs                   # Login/logout event records
api_error_logs            # Application error tracking
```
### **Dashboard Features**
- Real-time login event display
- Advanced filtering and search
- Column visibility customization
- Export functionality (CSV, Excel, Print)
- Responsive design for mobile devices

### **Reporting Capabilities**
- Time spent analysis per user
- Login frequency reports
- Failed authentication tracking
- Company-specific analytics

## 🛠️ **Configuration**

### **Environment Variables**
```bash
# Security
SECRET_KEY=your-secret-key-here
SESSION_COOKIE_SECURE=true

# Database
DATABASE_URL=sqlite:///database.db
# or: postgresql://user:pass@host:port/db
# or: mysql+pymysql://user:pass@host:port/db

# Application
APP_DEBUG=false
TIMEZONE=Europe/London

# Server
HOST=0.0.0.0
PORT=8000
SSL_CERTFILE=certs/cert.pem
SSL_KEYFILE=certs/key.pem
```

### **Configuration File Structure**
```ini
[app]           # Application settings
[database]      # Database connection
[server]        # Server configuration
[session]       # Session security
[security]      # Security headers
[cache]         # Static file caching
[proxy]         # Reverse proxy settings
[rate_limiting] # Rate limit configuration
```

## **Deployment Options**

### **Development**
```bash
# Install dependencies
pip install -r requirements.txt

# Generate SSL certificates
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 3650 -nodes

# Run application
python app.py
```

### **Production with Docker**
```dockerfile
FROM python:3.11-slim
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
```

### **Systemd Service**
```ini
[Unit]
Description=Domain Login Monitor
After=network.target

[Service]
Type=exec
User=www-data
WorkingDirectory=/opt/domain-logons
ExecStart=/opt/domain-logons/.venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

## 📡 **API Reference**

### **Authentication**
All API endpoints require `X-API-Key` header with valid API key.

### **Endpoints**

#### **POST /api/log_event**
Log authentication events from Windows clients.

**Request:**
```json
{
  "EventType": "Sign-In|Sign-Out|Lock",
  "UserName": "john.doe",
  "ComputerName": "WORKSTATION-01",
  "IPAddress": "192.168.1.100",
  "Timestamp": "2025-05-25T14:30:00Z",
  "retry": 0
}
```

**Response:**
```json
{
  "message": "Event logged successfully",
  "status": "success"
}
```

#### **POST /api/health**
Check system health and API connectivity.

**Response:**
```json
{
  "status": "ok",
  "message": "Health check passed",
  "timestamp": "2025-05-25T14:30:00+00:00",
  "database": "connected",
  "api_key_verified": true,
  "company_id": 1
}
```

## **Windows Client Integration**

### **Compiled Agent**
- **winagentUSM.exe**: Standalone Windows executable
- **Event Log Integration**: Monitors Windows Security events
- **Automatic Retry**: Built-in error handling and retry logic
- **Service Mode**: Can run as Windows service
- It is build with GO Lang

## **Default Credentials**

### **Initial Admin Account**
- **Username**: `superadmin`
- **Email**: `superadmin@example.com`
- **Password**: `adminsuper`
- **Role**: `GlobalAdmin`

### **API Key**
Initial API key is automatically generated for the admin account and displayed in Admin Settings.

## **Database Migration Support**

### **Supported Databases**
- **SQLite**: Default, perfect for small-medium deployments
- **PostgreSQL**: Recommended for production (best performance)
- **MySQL/MariaDB**: Enterprise environments
- **Microsoft SQL Server**: Corporate Windows environments

### **Migration Path**
1. Export data from current database
2. Update `config.ini` with new database connection
3. Run application to auto-create tables
4. Import data using provided migration scripts

## **Testing & Validation**

### **API Testing**
```bash
# Test login event
curl -k -X POST https://localhost:8000/api/log_event \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"EventType": "Sign-In", "UserName": "test", "ComputerName": "TEST-PC", "IPAddress": "192.168.1.100", "Timestamp": "2025-05-25T14:30:00Z"}'

# Test health check
curl -k -X POST https://localhost:8000/api/health \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY"
```

### **Web Interface Testing**
1. Navigate to `https://localhost:8000`
2. Login with default credentials
3. Create companies and users
4. Generate API keys
5. Test dashboard functionality

### **Additional Resources**
- **Configuration Reference**: `config.ini`
