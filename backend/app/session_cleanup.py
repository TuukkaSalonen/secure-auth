from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timezone
from .models import UserSession
from app import db
from .utils.logUtils import log_security_event

# Automatically clear expired sessions every 5 minutes
def clear_expired():
    from . import app
    with app.app_context():
        log_security_event("SESSION_CLEANUP", "CLEAR_EXPIRED_SESSIONS", None, "Clearing expired sessions", None)
        expired_sessions = UserSession.query.filter(UserSession.expires_at < datetime.now(timezone.utc)).all()
        for session in expired_sessions:
            db.session.delete(session)
        db.session.commit()

# Start the session cleanup scheduler
def start_cleanup_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=clear_expired, trigger="interval", minutes=5)
    scheduler.start()