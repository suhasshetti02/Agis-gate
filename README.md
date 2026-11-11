<div align="center">
  <img src="https://raw.githubusercontent.com/suhasshetti02/suhasshetti02/main/assets/projects/aegis-gate.svg" width="100%" alt="aegis-gate project banner"/>
</div>

---

# Aegis-Gate 🛡️

## AI-Enhanced Cryptographic Network Access Control System

Aegis-Gate is a secure, context-aware authentication platform designed to protect institute-style network access against credential theft, device spoofing, and suspicious login behavior.

Unlike traditional systems that rely only on username and password authentication, Aegis-Gate combines multiple layers of security including:

- RSA-2048 Cryptographic Authentication
- Device Fingerprinting
- OTP Verification
- AI-Based Risk Analysis
- Behavioral Biometrics
- Trusted Device Management
- Session Renewal
- Audit Logging
- Administrative Monitoring
- Simulated Network Access Control (IP/VLAN Provisioning)

The system follows a Defense-in-Depth approach where multiple independent security layers work together to verify both the user and the device before granting access.

---

# Problem Statement

In traditional college and institutional Wi-Fi systems, users authenticate using only a username and password. While this verifies the user identity, it does not verify the device being used.

As a result:

- Credentials can be shared.
- Credentials can be stolen.
- Unauthorized devices can access the network.
- Users are forced to repeatedly log in after session expiry.
- Administrators have limited visibility into suspicious login behavior.

Aegis-Gate addresses these issues by introducing device-based authentication, cryptographic verification, and AI-driven risk analysis.

---

# Objectives

- Verify both users and devices.
- Prevent unauthorized device access.
- Reduce repeated login requirements.
- Detect suspicious login behavior using AI.
- Provide centralized monitoring and auditing.
- Implement cryptographic challenge-response authentication.
- Support secure device registration and management.

---

# Key Features

### User Authentication

- Username and password verification
- Secure password hashing using PBKDF2-SHA256
- Failed login tracking

### Device Authentication

- Device fingerprint generation
- Trusted device registry
- Device trust scoring
- Maximum device limit per user

### Cryptographic Security

- RSA-2048 key pairs
- Challenge-response authentication
- Nonce generation
- Replay attack prevention

### OTP Verification

- Secure new-device registration
- OTP validation
- Device approval workflow

### AI Risk Analysis

- Isolation Forest anomaly detection
- Login behavior monitoring
- Risk score generation
- Adaptive authentication

### Behavioral Biometrics

- Typing speed analysis
- Keystroke rhythm analysis
- User behavior profiling

### Session Management

- Secure session tokens
- Trusted session renewal
- Session expiration handling

### Admin Dashboard

- User management
- Device management
- Risk monitoring
- Audit logs
- Security analytics

### Network Access Control (Simulated)

- Stateful IP Address allocation
- Role-based VLAN assignment (User vs Admin)
- Session-based network provisioning

---

# Technology Stack

| Layer | Technology |
|---------|------------|
| Backend | Python, Flask |
| Database | SQLite |
| Frontend | HTML, CSS, Bootstrap 5, JavaScript |
| Cryptography | RSA-2048, SHA-256 |
| Machine Learning | Scikit-Learn (Isolation Forest) |
| Authentication | Flask Sessions |
| Charts | Chart.js |

---

# Project Structure

```text
aegis-gate/
│
├── app.py
├── config.py
├── requirements.txt
│
├── ai/
│   ├── risk_engine.py
│   └── anomaly_detector.py
│
├── auth/
│   ├── rsa_handler.py
│   ├── nonce_handler.py
│   ├── otp_handler.py
│   ├── session_manager.py
│   └── device_registry.py
│
├── db/
│   └── database.py
│
├── network/
│   ├── network_controller.py
│   └── __init__.py
│
├── routes/
│   ├── auth_routes.py
│   ├── admin_routes.py
│   ├── dashboard_routes.py
│   └── api_routes.py
│
├── templates/
│
├── static/
│   ├── css/
│   ├── js/
│   └── img/
│
├── logs/
├── keys/
└── models/
```

---

# Database Overview

The system stores data in SQLite.

Main tables:

### Users

Stores:

- User information
- Password hashes
- Roles
- Account status

### Devices

Stores:

- Device fingerprints
- Public keys
- Trust scores
- Registration details

### OTP Codes

Stores:

- OTP values
- Expiry times
- Verification status

### Sessions

Stores:

- Active sessions
- Expiry timestamps
- Device associations

### Risk Scores

Stores:

- AI-generated scores
- Login analysis
- Risk reasons

### Audit Logs

Stores:

- Login activity
- Device registration
- Security events
- Administrative actions

---

# How the System Works

## Step 1: User Login

The user enters:

- Username
- Password

The system verifies credentials against the database.

---

## Step 2: Device Verification

The system checks whether the device is already trusted.

The browser generates a fingerprint using:

- Browser details
- Screen properties
- Platform information
- Device characteristics

---

## Step 3: OTP Verification

If the device is unknown:

- OTP is generated
- User verifies ownership
- Device registration begins

---

## Step 4: RSA Challenge-Response

The trusted device receives a random nonce.

The device signs the nonce using its private RSA key.

The server verifies the signature using the stored public key.

This proves ownership of the trusted device.

---

## Step 5: AI Risk Analysis

The AI engine analyzes:

- Login time
- Failed attempts
- Device history
- Behavioral biometrics
- Device switching frequency

The system generates a risk score.

Example:

```text
Risk Score: 0.78

Reasons:
- Unknown Device
- Unusual Login Time
- Multiple Failed Attempts
```

---

## Step 6: Access Decision

Based on the risk score:

### Low Risk

```text
Allow Access
```

### Medium Risk

```text
Request OTP Verification
```

### High Risk

```text
Block Access
```

---

## Step 7: Session Creation

A secure session is created.

The user gains access to the system.

---

## Step 8: Trusted Session Renewal

When a trusted device reconnects:

- Risk score is evaluated
- Session may be renewed automatically

This reduces repeated logins while maintaining security.

---

# How to Run

## 1. Create Virtual Environment

```cmd
python -m venv venv
```

---

## 2. Activate Virtual Environment

```cmd
venv\Scripts\activate
```

---

## 3. Install Dependencies

```cmd
pip install -r requirements.txt
```

---

## 4. Configure Application

Open the configuration file and set:

- SECRET_KEY
- ADMIN_PASSWORD

---

## 5. Start Application

```cmd
python app.py
```



---

## 6. Open Browser

```text
http://localhost:8888
```

---

# Demo Flow

```text
User Login
      ↓
Password Verification
      ↓
Device Fingerprint
      ↓
OTP (If Required)
      ↓
RSA Challenge
      ↓
AI Risk Analysis
      ↓
Session Creation
      ↓
Access Granted
```

---

# Admin Features

The administrator can:

- View users
- View devices
- Monitor risk scores
- Review audit logs
- Block users
- Block devices
- Monitor suspicious activity

---

# Security Features

- Password Hashing
- RSA-2048 Authentication
- Nonce Validation
- Replay Attack Protection
- OTP Verification
- Device Trust Scoring
- Behavioral Biometrics
- AI Risk Detection
- Session Management
- Audit Logging

---



# Viva Points

### Why RSA?

RSA allows devices to cryptographically prove their identity using a private key without exposing that key.

### Why Nonce?

A nonce prevents replay attacks by ensuring every authentication request is unique.

### Why AI?

AI helps detect suspicious login behavior that traditional authentication cannot identify.

### Why Device Fingerprinting?

Device fingerprinting helps recognize trusted devices and detect unknown devices.

### How does the system reduce repeated logins?

Trusted devices with low-risk behavior can receive automatic session renewal, reducing the need for repeated authentication.

### What makes Aegis-Gate different from normal login systems?

Normal systems verify only the user. Aegis-Gate verifies:

- User Identity
- Device Identity
- Cryptographic Ownership
- Behavioral Patterns
- Risk Level

before granting access.

---

# Conclusion

Aegis-Gate is a multi-layered authentication and access control platform that combines cryptography, artificial intelligence, behavioral analysis, and device trust management to provide a secure and intelligent authentication experience for institutional environments.

---

# Screenshots

<div align="center">
  <img src="results/Screenshot%202026-08-30%20155315.png" width="49%" alt="Aegis-Gate authentication screen"/>
  <img src="results/Screenshot%202026-08-30%20163003.png" width="49%" alt="Aegis-Gate dashboard"/>
  <img src="results/Screenshot%202026-08-30%20163018.png" width="49%" alt="Aegis-Gate access-control view"/>
  <img src="results/Screenshot%202026-08-30%20163040.png" width="49%" alt="Aegis-Gate administration view"/>
</div>
