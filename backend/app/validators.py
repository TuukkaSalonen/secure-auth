import re
from password_validator import PasswordValidator
import uuid

# Password validation schema
password_schema = PasswordValidator()
password_schema\
    .min(8)\
    .max(64)\
    .has().uppercase()\
    .has().lowercase()\
    .has().digits()\
    .has().no().spaces()

# MFA code validation schema
mfa_code_schema = PasswordValidator()
mfa_code_schema\
    .min(4)\
    .max(6)\
    .has().digits()\
    .has().no().spaces()

# Email and username regex patterns
email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
username_regex = r'^[a-zA-Z0-9_]+$'

# Function to validate the input for user basic login/registration
def check_login_input(username, password):
    if not username or not password:
        return False, "Username/Email and password are required"

    if not (2 <= len(username) <= 32) or (not re.fullmatch(username_regex, username) and not re.fullmatch(email_regex, username)):
        return False, "Invalid username/email format"

    if not password_schema.validate(password):
        return False, "Invalid password format (8-64 chars, at least one uppercase, lowercase, and digit, no spaces)"

    return True, "Valid input"

# Function to validate the input for login with MFA code
def check_mfa_input(code):
    if not code:
        return False, "Code is required"

    if not mfa_code_schema.validate(code):
        return False, "Invalid code format (4-6 digits)"

    return True, "Valid input"

# Function to validate the input for file id
def check_file_id(file_id):
    if not file_id:
        return False, "File ID is required"
    try:
        file_uuid = uuid.UUID(file_id, version=4)
        return str(file_uuid) == file_id
    except ValueError:
        return False
