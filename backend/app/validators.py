import re

def check_login_input(username, password):
    if not username or not password:
        return False, "Username and password are required"

    if not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
        return False, "Invalid username format"

    if len(password) < 8 or len(password) > 64:
        return False, "Invalid password length"

    return True, "Valid input"

def check_mfa_input(username, code):
    if not username:
        return False, "Username is required"
    
    if not code:
        return False, "Code is required"
    
    if not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
        return False, "Invalid username format"

    if len(code) != 4 and len(code) != 6:
        return False, "Invalid code length"

    return True, "Valid input"