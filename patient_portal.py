"""
Medical Communication System - Patient Portal

A command-line patient portal that lets patients register, log in, manage
appointments, and view their medical records, prescriptions, and notifications.

Originally built as a 3-person team project for an Intro to Python course.
"""

import hashlib
import secrets

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# Each patient gets their own entry in this dictionary (keyed by username),
# so a new sign-up never overwrites another patient's information.

patients = {}

appointment_counter = 10000

# The session tracker starts empty, so a patient is forced to log in
# before they can see or change any personal information.
current_session = None

SPECIAL_CHARACTERS = "!@#$%^&*()_+"
MIN_PASSWORD_LENGTH = 13


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

def hash_password(password, salt=None):
    """
    Hashes a password with a random salt so plain-text passwords are never stored.

    Arguments:
        password (string): The plain-text password
        salt (string): An existing salt to reuse when checking a password (optional)

    Returns:
        tuple: (salt, hashed_password) as hex strings
    """
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000)
    return salt, hashed.hex()


def verify_password(patient_username, password):
    """
    Checks a password against the stored salted hash for that patient.

    Returns:
        bool: True if the password is correct
    """
    record = patients[patient_username]
    _, hashed = hash_password(password, record["salt"])
    return secrets.compare_digest(hashed, record["password_hash"])


def validate_password(password):
    """
    Checks that a password meets the security requirements.

    Returns:
        string: An error message, or an empty string if the password is valid
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return "Password must be longer than 12 characters."

    has_special = False
    for char in password:
        if char in SPECIAL_CHARACTERS:
            has_special = True

    if not has_special:
        return "Password must contain at least one special character."
    return ""


def require_login():
    """
    Returns an error message if nobody is logged in, otherwise an empty string.
    """
    if current_session is None or current_session not in patients:
        return "Access Denied: You must login first."
    return ""


# ---------------------------------------------------------------------------
# Database functions
# ---------------------------------------------------------------------------

def store_patient_data(patient_name, patient_username, patient_password, patient_phone, patient_email):
    """
    Saves all the patient information, including their (hashed) login credentials.

    Arguments:
        patient_name (string): The full name of the patient
        patient_username (string): The account username
        patient_password (string): The account password (stored as a salted hash)
        patient_phone (string): The patient's phone number
        patient_email (string): The patient's email

    Returns:
        string: A message confirming the data has been stored.
    """
    # Defensive coding: treating the phone as a string avoids issues with leading zeros
    if type(patient_phone) != str:
        return "Error: Phone must be entered as a string (ex. '123456789')"

    salt, password_hash = hash_password(patient_password)

    patients[patient_username] = {
        "name": patient_name,
        "salt": salt,
        "password_hash": password_hash,
        "phone": patient_phone,
        "email": patient_email,
        "medical_history": "No History",
        "prescription_med": "No Current Medication",
        "prescription_dosage": "",
        "alert_msg": "",
        "appt_id": "",
        "appt_date": "",
        "appt_time": "",
        "appt_dept": "",
        "appt_status": "No appointment",
    }
    return "Success: Profile has been saved."


def store_medical_history(patient_username, patient_medical_history):
    """
    Stores a patient's medical history and links it to their username.

    Returns:
        string: A message confirming the medical information has been stored.
    """
    if patient_username not in patients:
        return "The patient has not been found in the system."

    patients[patient_username]["medical_history"] = patient_medical_history
    return "Success: Patient history has been updated for this user!"


def store_appointment_log(patient_username, appointment_date, appointment_time,
                          appointment_department, appointment_status, appointment_id):
    """
    Saves a patient's appointment details.

    Returns:
        string: Confirmation message of the appointment log entry.
    """
    if patient_username not in patients:
        return "Patient was not found in the system."

    record = patients[patient_username]
    record["appt_id"] = appointment_id
    record["appt_date"] = appointment_date
    record["appt_time"] = appointment_time
    record["appt_dept"] = appointment_department
    record["appt_status"] = appointment_status
    return "Success: Appointment has been logged."


def store_prescription_data(patient_username, patient_medication, patient_medication_dosage):
    """
    Stores a patient's prescription record.

    Returns:
        string: A message confirming the prescription data has been stored.
    """
    if patient_username not in patients:
        return "Patient has not been found in the system."

    patients[patient_username]["prescription_med"] = patient_medication
    patients[patient_username]["prescription_dosage"] = patient_medication_dosage
    return "Success: Prescription data has been stored."


def store_notification_log(patient_username, notification):
    """
    Records a notification or alert sent to a specific patient.

    Returns:
        string: A message confirming the notification has been stored.
    """
    if patient_username not in patients:
        return "Patient has not been found in the system."

    patients[patient_username]["alert_msg"] = notification
    return "Success: Notification log has been stored."


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def signup_user(patient_name, patient_username, patient_password, patient_email, patient_phone):
    """
    Registers a new patient after validating every field.

    Returns:
        string: A message confirming the account creation or an error message.
    """
    if patient_name == "" or patient_username == "":
        return "Sign-Up Failed: Name and username are required."

    # Prevents one patient from taking another patient's username
    if patient_username in patients:
        return "Sign-Up Failed: That username is already taken. Please choose another."

    # Phone must be a string made only of numbers
    if type(patient_phone) != str or patient_phone == "":
        return "Sign-Up Failed: Please enter a phone number (ex. '123456789')."
    for char in patient_phone:
        if char not in "0123456789":
            return "Sign-Up Failed: Phone must only contain numbers."

    # Basic email format check
    if "@" not in patient_email or "." not in patient_email:
        return "Sign-Up Failed: Invalid email format."

    password_error = validate_password(patient_password)
    if password_error:
        return f"Sign-Up Failed: {password_error}"

    store_patient_data(patient_name, patient_username, patient_password, patient_phone, patient_email)
    return f"Success: Account has been created. Welcome, {patient_name}!"


def login_user(patient_username, patient_password):
    """
    Verifies a patient's identity and starts their session.

    Returns:
        string: A message confirming the login or an error message.
    """
    global current_session

    if patient_username == "" or patient_password == "":
        return "Login Failed: Please enter both username and password."

    # The same message is used for a wrong username or wrong password,
    # so an attacker can't tell which usernames exist.
    if patient_username not in patients or not verify_password(patient_username, patient_password):
        return "Login Failed: Incorrect username or password."

    current_session = patient_username
    return f"Success: Login successful. Welcome back, {patient_username}!"


def logout_user():
    """
    Ends the current session.
    """
    global current_session
    current_session = None
    return "Success: You have been logged out."


def password_management(patient_username, old_password, new_password):
    """
    Changes a patient's password after verifying the old one.

    Returns:
        string: A message confirming the update or explaining why it failed.
    """
    if patient_username not in patients:
        return "Password Update Failed: Username not found."

    if not verify_password(patient_username, old_password):
        return "Password Update Failed: The old password you entered is incorrect."

    if new_password == old_password:
        return "Password Update Failed: New password cannot be the same as the old password."

    password_error = validate_password(new_password)
    if password_error:
        return f"Password Update Failed: {password_error}"

    salt, password_hash = hash_password(new_password)
    patients[patient_username]["salt"] = salt
    patients[patient_username]["password_hash"] = password_hash
    return f"Success: Password has been updated for {patient_username}!"


# ---------------------------------------------------------------------------
# Appointment management (requires login)
# ---------------------------------------------------------------------------

def validate_date_time(date, time):
    """
    Checks the appointment date and time format.

    Returns:
        string: An error message, or an empty string if both are valid
    """
    if len(date) != 10 or date[2] != "/" or date[5] != "/":
        return "Please enter date as MM/DD/YYYY (ex. 08/09/2004)."
    if "AM" not in time.upper() and "PM" not in time.upper():
        return "Please specify AM or PM for your appointment time."
    return ""


def schedule_appointment(date, time, department):
    """
    Schedules an appointment for the logged-in patient.

    Returns:
        string: A confirmation message with the new appointment ID, or an error message.
    """
    global appointment_counter

    login_error = require_login()
    if login_error:
        return login_error

    if date == "" or time == "" or department == "":
        return "Scheduling Failed: All fields are needed to schedule an appointment."

    format_error = validate_date_time(date, time)
    if format_error:
        return f"Scheduling Failed: {format_error}"

    appointment_counter += 1
    appointment_id = "APT-" + str(appointment_counter)
    store_appointment_log(current_session, date, time, department, "Scheduled", appointment_id)
    return (f"Success: Appointment {appointment_id} has been scheduled! "
            f"Save this ID to cancel or change your appointment.")


def update_appointment(appointment_id, new_date, new_time, new_dept):
    """
    Updates the logged-in patient's appointment. Any field left blank keeps its current value.

    Returns:
        string: A message confirming the updated appointment or an error message.
    """
    login_error = require_login()
    if login_error:
        return login_error

    record = patients[current_session]

    # Patients can only change their own appointment
    if appointment_id == "" or appointment_id != record["appt_id"]:
        return "Update Failed: Appointment ID not found on your account."

    final_date = record["appt_date"] if new_date == "" else new_date
    final_time = record["appt_time"] if new_time == "" else new_time
    final_dept = record["appt_dept"] if new_dept == "" else new_dept

    format_error = validate_date_time(final_date, final_time)
    if format_error:
        return f"Update Failed: {format_error}"

    store_appointment_log(current_session, final_date, final_time, final_dept, "Updated", appointment_id)
    return f"Success: Appointment {appointment_id} is now set for {final_dept} on {final_date} at {final_time}!"


def cancel_appointment(appointment_id, confirm_cancel):
    """
    Cancels the logged-in patient's appointment after they confirm.

    Returns:
        string: A message confirming the cancellation or an error message.
    """
    login_error = require_login()
    if login_error:
        return login_error

    if not confirm_cancel:
        return "Cancellation Failed: No changes were made to your current appointment."

    if appointment_id == "" or appointment_id != patients[current_session]["appt_id"]:
        return "Cancellation Failed: Appointment ID not found on your account."

    store_appointment_log(current_session, "N/A", "N/A", "N/A", "Cancelled", appointment_id)
    return "Success: Appointment has been cancelled."


# ---------------------------------------------------------------------------
# Medical records, prescriptions, and notifications (requires login)
# ---------------------------------------------------------------------------

def view_my_records():
    """
    Builds a formatted medical report for the logged-in patient.

    Returns:
        string: A formatted medical report or an error message.
    """
    login_error = require_login()
    if login_error:
        return login_error

    record = patients[current_session]
    report = "\n--- OFFICIAL MEDICAL RECORD ---"
    report += f"\nPatient Name:         {record['name']}"
    report += f"\nMedical History:      {record['medical_history']}"
    report += f"\nActive Medication:    {record['prescription_med']}"
    report += f"\nAppointment:          {record['appt_date']} {record['appt_time']} ({record['appt_status']})"
    return report


def check_my_prescriptions():
    """
    Shows the logged-in patient's active prescription.

    Returns:
        string: The prescription details or a 'no prescriptions' message.
    """
    login_error = require_login()
    if login_error:
        return login_error

    record = patients[current_session]
    if record["prescription_med"] == "No Current Medication":
        return "You currently have no active prescriptions on file."

    report = "\n--- YOUR PRESCRIPTIONS ---"
    report += f"\nMedication: {record['prescription_med']}"
    report += f"\nDosage:     {record['prescription_dosage']}"
    report += "\n--------------------------"
    return report


def check_notifications():
    """
    Shows the logged-in patient's latest notification.

    Returns:
        string: The alert message or a 'no notifications' message.
    """
    login_error = require_login()
    if login_error:
        return login_error

    msg = patients[current_session]["alert_msg"] or "You have no new notifications."
    return f"\n*** NOTIFICATION ***\n{msg}\n********************"


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

def display_patient_menu():
    """
    Displays the available services in the Patient Portal.
    """
    print("\n" + "=" * 50)
    print("       WELCOME TO THE PATIENT PORTAL")
    if current_session:
        print(f"       Logged in as: {current_session}")
    print("=" * 50)
    print("  1. register           - Creates a new account")
    print("  2. login              - Gives you access to your account")
    print("  3. change password    - Updates your password")
    print("  4. schedule           - Books an appointment")
    print("  5. update appt        - Changes the appointment details")
    print("  6. cancel appt        - Cancels an appointment")
    print("  7. check results      - View your medical records")
    print("  8. check prescription - See your medications")
    print("  9. check alerts       - View notifications")
    print("  10. logout            - Ends your session")
    print("  0. exit               - Quit the application")


def handle_register():
    print("\n--- NEW PATIENT REGISTRATION ---")
    patient_name = input("  Full name:        ").strip()
    patient_username = input("  Choose username:  ").strip()
    patient_password = input("  Choose password:  ").strip()
    patient_email = input("  Email address:    ").strip()
    patient_phone = input("  Phone number:     ").strip()
    print(f"\n  >> {signup_user(patient_name, patient_username, patient_password, patient_email, patient_phone)}")


def handle_login():
    print("\n--- PATIENT LOGIN ---")
    patient_username = input("  Username: ").strip()
    patient_password = input("  Password: ").strip()
    print(f"\n  >> {login_user(patient_username, patient_password)}")


def handle_change_password():
    print("\n--- CHANGE PASSWORD ---")
    patient_username = input("  Username:     ").strip()
    old_password = input("  Old password: ").strip()
    new_password = input("  New password: ").strip()
    print(f"\n  >> {password_management(patient_username, old_password, new_password)}")


def handle_schedule():
    print("\n--- SCHEDULE AN APPOINTMENT ---")
    date = input("  Date (MM/DD/YYYY):   ").strip()
    time = input("  Time (HH:MM AM/PM):  ").strip()
    department = input("  Department:          ").strip()
    print(f"\n  >> {schedule_appointment(date, time, department)}")


def handle_update_appt():
    print("\n--- UPDATE APPOINTMENT (leave blank to keep current) ---")
    appointment_id = input("  Appointment ID:          ").strip()
    new_date = input("  New date (MM/DD/YYYY):   ").strip()
    new_time = input("  New time (HH:MM AM/PM):  ").strip()
    new_dept = input("  New department:          ").strip()
    print(f"\n  >> {update_appointment(appointment_id, new_date, new_time, new_dept)}")


def handle_cancel_appt():
    print("\n--- CANCEL APPOINTMENT ---")
    appointment_id = input("  Appointment ID: ").strip()
    confirm = input("  Confirm cancel? (yes/no): ").strip().lower() == "yes"
    print(f"\n  >> {cancel_appointment(appointment_id, confirm)}")


def handle_logout():
    print(f"\n  >> {logout_user()}")


def main():
    """
    Main controller: shows the menu and routes each choice to its handler.
    """
    actions = {
        "1": handle_register, "register": handle_register,
        "2": handle_login, "login": handle_login,
        "3": handle_change_password, "change password": handle_change_password,
        "4": handle_schedule, "schedule": handle_schedule,
        "5": handle_update_appt, "update appt": handle_update_appt,
        "6": handle_cancel_appt, "cancel appt": handle_cancel_appt,
        "7": lambda: print(view_my_records()), "check results": lambda: print(view_my_records()),
        "8": lambda: print(check_my_prescriptions()), "check prescription": lambda: print(check_my_prescriptions()),
        "9": lambda: print(check_notifications()), "check alerts": lambda: print(check_notifications()),
        "10": handle_logout, "logout": handle_logout,
    }

    while True:
        display_patient_menu()
        try:
            choice = input("\n  Enter your choice: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  Session interrupted. Goodbye!")
            break

        if choice in ("0", "exit"):
            print("  Thank you for using the Patient Portal. Stay healthy!")
            break

        if choice in actions:
            try:
                actions[choice]()
            except Exception as error:
                print(f"\n  An unexpected error occurred: {error}")
                print("  Please try again.")
        else:
            print("\n  !! Invalid option. Please type a menu number or keyword.")

        try:
            input("\n  Press Enter to return to the main menu...")
        except (KeyboardInterrupt, EOFError):
            break


# ---------------------------------------------------------------------------
# Sample data (fake test patients)
# ---------------------------------------------------------------------------

def load_sample_data():
    """
    Loads two fake test patients so the portal can be tried right away.
    """
    store_patient_data("John Doe", "jdoe1", "Password!@#123", "2035550101", "jdoe@email.com")
    store_medical_history("jdoe1", "Seasonal Allergies, Mild Asthma")
    store_prescription_data("jdoe1", "Albuterol", "2 puffs as needed")
    store_notification_log("jdoe1", "Upcoming inhaler pick up at your nearest pharmacy")

    store_patient_data("Jane Smith", "jsmith2", "SecurePass!@#456", "2035550202", "jsmith@email.com")
    store_medical_history("jsmith2", "Diabetes")
    store_prescription_data("jsmith2", "Insulin", "20 units of long-acting insulin once daily")
    store_notification_log("jsmith2", "Upcoming yearly check up")


if __name__ == "__main__":
    load_sample_data()
    main()
