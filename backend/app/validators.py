import os
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

# Function to validate the file type
def validate_file_type(file):
    mimetype = file.mimetype
    extension = os.path.splitext(file.filename)[1].lower()

    allowed_exts = ALLOWED_FILE_TYPES.get(mimetype)
    return allowed_exts and extension in allowed_exts

# Allowed file types and their corresponding MIME types, same as in the frontend
ALLOWED_FILE_TYPES = {
    "image/jpeg": [".jpg", ".jpeg"],
    "image/png": [".png"],
    "image/gif": [".gif"],
    "image/svg+xml": [".svg"],
    "image/webp": [".webp"],
    "image/bmp": [".bmp"],
    "image/tiff": [".tif", ".tiff"],
    "audio/mpeg": [".mp3"],
    "audio/wav": [".wav"],
    "audio/ogg": [".ogg"],
    "audio/mp4": [".m4a"],
    "audio/flac": [".flac"],
    "audio/aac": [".aac"],
    "video/mp4": [".mp4"],
    "video/mpeg": [".mpeg"],
    "video/ogg": [".ogv"],
    "video/webm": [".webm"],
    "video/quicktime": [".mov"],
    "video/x-msvideo": [".avi"],
    "video/x-matroska": [".mkv"],
    "application/pdf": [".pdf"],
    "application/msword": [".doc", ".docx"],
    "application/vnd.ms-excel": [".xls", ".xlsx"],
    "application/vnd.ms-powerpoint": [".ppt", ".pptx"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [".docx"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [".xlsx"],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": [".pptx"],
    "text/plain": [".txt", ".py", ".js", ".html", ".css", ".ts", ".c", ".cpp", ".java", ".jsx", ".tsx", ".json", ".md", ".xml", ".csv", ".yaml", ".yml", ".sql", ".hs", ".sh", ".bat", ".ini", ".log"],
    "application/zip": [".zip", ".tar", ".gz", ".7z", ".rar"],
    "application/x-tar": [".tar"],
    "application/gzip": [".gz"],
    "application/json": [".json"],
    "application/xml": [".xml"],
    "application/x-yaml": [".yaml", ".yml"],
    "application/octet-stream": [".bin", ".exe", ".iso"],
    "application/x-msdownload": [".exe", ".msi"],
    "application/x-shockwave-flash": [".swf"],
    "application/x-bzip": [".bz2"],
    "application/x-bzip2": [".bz2"],
    "application/x-rar-compressed": [".rar"],
}
