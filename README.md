# Medical Communication System – Patient Portal

A command-line patient portal written in Python. Patients can create an account, log in securely, manage appointments, and view their medical records, prescriptions, and notifications.

Built as a 3-person team project for an Intro to Python course at CT State Community College, then improved with security and bug fixes.

## Features

- **Account registration** with input validation (phone, email, password strength)
- **Secure login**: passwords are hashed with a random salt (PBKDF2-SHA256) and never stored in plain text
- **Session-based access control**: patients must log in before viewing or changing any personal data
- **Appointments**: schedule, update, and cancel, with each appointment given a unique ID
- **Medical records**: view history, active medication, and appointment status
- **Prescriptions and notifications**: check current medication, dosage, and alerts
- **Password management**: change password after verifying the old one

## How to run

Requires Python 3.8+ (no extra packages).

```bash
python3 patient_portal.py
```

Two fake test patients are loaded so you can try it right away:

| Username | Password |
| --- | --- |
| jdoe1 | Password!@#123 |
| jsmith2 | SecurePass!@#456 |

All sample data is fictional.

## Example

```
==================================================
       WELCOME TO THE PATIENT PORTAL
==================================================
  1. register           - Creates a new account
  2. login              - Gives you access to your account
  ...
  Enter your choice: 2

--- PATIENT LOGIN ---
  Username: jdoe1
  Password: Password!@#123

  >> Success: Login successful. Welcome back, jdoe1!
```

## Security improvements

After the original class version, I made these changes:

- **Password hashing**: replaced plain-text password storage with salted PBKDF2-SHA256 hashes
- **Access control**: appointment actions now require login and only work on the logged-in patient's own appointment
- **Safer login errors**: the same message is shown for a wrong username or wrong password, so attackers can't find valid usernames
- **Bug fixes**: fixed a crash when checking prescriptions before logging in, fixed appointment updates when a field was left blank, and fixed the script failing to run outside of Colab

## Team

Marina Medrano (project lead): designed the system layout and structure, built the core modules (database, authentication, appointments, records, prescriptions, notifications, and CLI), integrated and tested the full application, presented the final project, and later added the security improvements

Shilvi and Rohan: helped review and clean up the code
## Tech

Python · hashlib · secrets · command-line interface
