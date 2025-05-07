from ..config import logger

# Function to log security events
def log_security_event(route, event, user_id=None, message=None, extra_data=None):
    log_message = {
        "route": route,
        "event": event,
        "user_id": user_id,
        "message": message,
        "extra_data": extra_data,
    }
    logger.info(log_message)