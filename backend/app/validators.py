import re
from password_validator import PasswordValidator

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

# Function to validate the input for user basic login/registration
def check_login_input(username, password):
    if not username or not password:
        return False, "Username and password are required"
    
    if not (2 <= len(username) <= 32) or not re.fullmatch(r'^[a-zA-Z0-9_]+$', username):
        return False, "Invalid username format"

    if not password_schema.validate(password):
        return False, "Invalid password format (8-64 chars, at least one uppercase, lowercase, and digit, no spaces)"

    return True, "Valid input"

# Function to validate the input for login with MFA code
def check_mfa_input(username, code):
    if not username:
        return False, "Username is required"
    
    if not code:
        return False, "Code is required"
    
    if not (2 <= len(username) <= 32) or not re.fullmatch(r'^[a-zA-Z0-9_]+$', username):
        return False, "Invalid username format"

    if not mfa_code_schema.validate(code):
        return False, "Invalid code format (4-6 digits)"

    return True, "Valid input"