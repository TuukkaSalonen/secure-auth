import os
from .config import Config 
from datetime import datetime
import subprocess
from .utils.logUtils import log_security_event
from apscheduler.schedulers.background import BackgroundScheduler

# Backup the database every day
def backup_database():
    dir = Config.BACKUP_DIR
    if not os.path.exists(dir):
        os.makedirs(dir)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_file = os.path.join(dir, f"db_backup_{timestamp}.sql")

    database_url = Config.SQLALCHEMY_DATABASE_URI
    if not database_url:
        log_security_event("DB_BACKUP", "BACKUP_ERROR", None, f"Database URL not set in config", None)
        return
    try:
        subprocess.run(
            ["pg_dump", "--dbname", database_url, "-f", backup_file, "--encoding", "UTF8"],
            check=True,
        )
        log_security_event("DB_BACKUP", "BACKUP_SUCCESS", None, f"Database backup created at {backup_file}", "Date: " + str(datetime.now()))
        
        manage_backup_files(dir)
    
    except Exception as e:
        log_security_event("DB_BACKUP", "BACKUP_ERROR", None, f"Error creating database backup: {str(e)}", None)

# Manage backup files to keep only the latest 10 backups
def manage_backup_files(dir, max_files=10):
    backup_files = sorted(
        [os.path.join(dir, f) for f in os.listdir(dir) if f.endswith(".sql")],
        key=os.path.getctime
    )
    while len(backup_files) > max_files:
        oldest_file = backup_files.pop(0)
        os.remove(oldest_file)
        log_security_event("DB_BACKUP", "BACKUP_FILE_DELETED", None, f"Deleted old backup file: {oldest_file}", None)

# Start the backup scheduler
def start_backup_scheduler():
    backup_scheduler = BackgroundScheduler()
    backup_scheduler.add_job(func=backup_database, trigger="interval", hours=12)
    backup_scheduler.start()
    log_security_event("DB_BACKUP", "SCHEDULER_STARTED", None, "Backup scheduler started", None)