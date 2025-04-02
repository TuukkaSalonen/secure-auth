from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timezone
from .models import UserSession
from app import db

# Automatically clear expired sessions every 5 minutes
def clear_expired():
    from . import app
    with app.app_context():
        print("Clearing expired sessions")
        expired_sessions = UserSession.query.filter(UserSession.expires_at < datetime.now(timezone.utc)).all()
        for session in expired_sessions:
            db.session.delete(session)
        db.session.commit()

scheduler = BackgroundScheduler()
scheduler.add_job(func=clear_expired, trigger="interval", minutes=5)