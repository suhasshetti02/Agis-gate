# Aegis-Gate — Context-Aware Network Access Control Prototype

Aegis-Gate is a Flask-based authentication and device-trust prototype. It combines password authentication, device registration, OTP verification, RSA challenge-response, login-risk scoring, session management, audit logging, and simulated IP/VLAN allocation.

> **Project status:** Security research / academic prototype. Network allocation is simulated in SQLite; it does not configure a real switch, access point, RADIUS server, or production VLAN. The risk engine is a decision-support signal, not a formally validated intrusion-detection system.

## Implemented capabilities

- Password authentication with Werkzeug password hashing.
- Failed-login tracking and temporary account lockout.
- Device fingerprint registration and trusted-device management.
- Email-delivered OTP verification for new-device workflows.
- RSA key generation and RSA-PSS challenge signing / verification.
- Nonce generation and one-time challenge validation.
- Session creation, validation, expiration, and renewal helpers.
- Rule-based risk scoring using login history, device trust, IP, and behavior signals.
- Per-user Isolation Forest anomaly model when enough login history exists.
- Typing-dynamics collection (average dwell time, flight time, and typing speed); actual typed characters are not recorded by that script.
- Admin dashboards, audit logging, and simulated IP/VLAN allocation.

## Technology stack

| Layer | Technologies |
|---|---|
| Backend | Python, Flask, Flask-Login / Flask-WTF components |
| Database | SQLite |
| Authentication | Werkzeug password hashing, Flask sessions, OTP |
| Cryptography | Python cryptography, RSA-PSS, SHA-256 |
| Risk analysis | scikit-learn Isolation Forest and rule-based scoring |
| Frontend | Jinja templates, HTML, CSS, Bootstrap 5, JavaScript |
| Notifications | SMTP email |

## Repository structure

- `app.py` — Flask application factory and local entry point.
- `config.py` — environment-based settings.
- `auth/` — RSA, nonce, OTP, session, and device-registry helpers.
- `ai/` — risk scoring and anomaly detection.
- `db/database.py` — SQLite initialization and data access.
- `network/network_controller.py` — simulated IP/VLAN allocation.
- `routes/` — auth, admin, dashboard, and API blueprints.
- `static/` — browser-side behavior, device, and dashboard scripts.
- `templates/` — server-rendered interface.
- `tests/test_aegis.py` — unit / integration-style tests.

## Run locally

Requirements: Python compatible with the pinned dependencies.

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
# Activate the environment, then:
pip install -r requirements.txt
```

2. Configure the required variables:

```bash
cp .env.example .env
```

At minimum, configure the required `SECRET_KEY` and `ADMIN_PASSWORD`. Configure SMTP settings if email OTP delivery is required. Keep the file local and never commit secrets.

3. Start the application:

```bash
python app.py
```

The local entry point listens on port `8888` and binds to `0.0.0.0`; restrict network exposure as appropriate.

## How the authentication flow works

1. User submits username/password and device details.
2. The application checks credentials and failed-login / lockout state.
3. Device trust is checked against the local device registry.
4. New or untrusted devices can be required to complete OTP verification.
5. A nonce challenge can be signed with the device's RSA private key and verified with its registered public key.
6. Risk signals are combined to determine whether to allow, step up, or block an access attempt.
7. The application creates a session and records audit information.
8. The network controller records an IP and VLAN allocation in SQLite for the session.

## Testing

Run the test module from the project root:

```bash
python -m unittest discover -s tests -v
```

The current test file should be reviewed before treating the suite as passing; it uses `Path(...)` without importing `Path` in its visible imports. No claim of passing CI is made here.

## Security limitations

- Browser/device fingerprints are signals, not unforgeable hardware identities.
- Typing dynamics are collected from password-field timing and can be noisy; do not treat them as biometric proof.
- The Isolation Forest is trained from the user's recent login history only when sufficient rows are available. When no model is available, the anomaly adjustment returns a neutral result.
- The IP/VLAN controller only allocates records in SQLite. It does not make network infrastructure changes.
- Protect server RSA private-key files, SQLite database files, session secrets, SMTP credentials, and the admin password.
- Use HTTPS, secure session-cookie settings, rate limits, robust logging, and hardened deployment settings before exposing the app publicly.
- Review debug mode and the `0.0.0.0` bind address before deployment.

## License

See repository and dependency licenses.
