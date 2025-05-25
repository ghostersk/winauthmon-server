# Domain Login Monitoring System
## Setup Instructions
#### pip install flask flask_sqlalchemy flask_bcrypt flask_login flask_wtf flask_bootstrap email-validator pyotp qrcode pillow

### 1. Generate SSL Certificate
First, generate a self-signed certificate using OpenSSL:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
```
### Testing the app functionality from terminal:
```
curl -k -X POST -H "Content-Type: application/json" -H "X-API-Key: 47959c6d5d8db64eb0ec3ad824ccbe82618632e2a58823d84aba92078da693fa" -d '{"EventType": "Test", "UserName": "Testuser", "ComputerName": "TEST-PC", "IPAddress": "192.168.1.100", "Timestamp": "2025-04-27 08:50:35 BST", "retry": 1}' https://localhost:5000/api/log_event

curl -k -X POST -H "Content-Type: application/json" -H "X-API-Key: 47959c6d5d8db64eb0ec3ad824ccbe82618632e2a58823d84aba92078da693fa" -d '{"EventType": "Test", "UserName": "Testuser", "ComputerName": "TEST-PC", "IPAddress": "192.168.1.100", "Timestamp": "2025-04-27 08:51:35Z"}' https://localhost:8000/api/log_event
```

### 2. PowerShell Script
Save this script as LogEvent.ps1:

```powershell
function Send-LogData {
    param (
        [string]$EventType,
        [string]$ApiKey  # Add your API key here
    )

    # Get the user name and computer name
    $UserName = $env:USERNAME
    $ComputerName = $env:COMPUTERNAME

    # Get the IP address of the default network interface
    $IPAddress = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
        $_.InterfaceAlias -match "Ethernet|Wi-Fi" -and $_.IPAddress -ne "127.0.0.1"
    } | Select-Object -ExpandProperty IPAddress -First 1

    # Get the current timestamp in ISO format
    $Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Prepare the log data
    $LogData = @{
        EventType = $EventType
        UserName = $UserName
        ComputerName = $ComputerName
        IPAddress = $IPAddress
        Timestamp = $Timestamp
    }

    # Convert the log data to JSON
    $LogJson = $LogData | ConvertTo-Json

    # Send the log data using Invoke-RestMethod
    try {
        $response = Invoke-RestMethod -Uri "https://yourserver.com:5000/log_event" `
            -Method Post `
            -Body $LogJson `
            -Headers @{
                "Content-Type" = "application/json"
                "X-API-Key" = $ApiKey
            } `
            -SkipCertificateCheck
        Write-Host "Log sent successfully: $EventType"
    }
    catch {
        Write-Error "Failed to send log: $_"
    }
}
```

### 3. Task Scheduler Setup
Create Tasks for Each Event:

#### User Sign-In:
1. Open Task Scheduler
2. Click Create Task
3. Name the task (e.g., "Log User Sign-In")
4. Go to the Triggers tab and click New
5. Select On an event
6. Set Log to Security and Source to Microsoft-Windows-Security-Auditing
7. Set Event ID to 4624 (successful logon)
8. Go to the Actions tab and click New
9. Set Action to Start a program
10. Set Program/script to powershell.exe
11. Set Add arguments to: 
```
-File "C:\Path\To\LogEvent.ps1" -EventType "Sign-In" -ApiKey "YOUR_API_KEY_HERE"
```

#### PC Lock:
Same as above but:
- Set Event ID to 4800 (workstation lock)
- Change EventType to "Lock"

#### User Sign-Out:
Same as above but:
- Set Event ID to 4647 (user initiated logoff)
- Change EventType to "Sign-Out"

### 4. Initial Setup
1. Log in to the web interface using default credentials:
   - Username: superadmin
   - Password: adminsuper
   - Email: superadmin@example.com
2. Go to Admin Settings to generate an API key
3. Update all task scheduler tasks with the generated API key

### For compiling you would need pyinstall with optional upx
https://upx.github.io/

```

flask_app/
│
├── app.py
├── config.py
├── models.py
├── forms.py
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── logs.html
│   └── manage_users.html
├── static/
│   ├── css/
│   └── js/
└── database.db
```