import psycopg2
from sqlalchemy import datetime
import jwt

def store_tokens_in_db(user_id: str, access_token: str, refresh_token: str, csrf_access_token: str, csrf_refresh_token: str, expiration: int):
    # Connect to PostgreSQL
    conn = psycopg2.connect("dbname=test user=postgres password=secret")
    cursor = conn.cursor()

    # Calculate expiration time from the JWT token's expiration (in Unix timestamp format)
    expires_at = datetime.utcfromtimestamp(expiration)

    # Insert tokens into the user_sessions table
    cursor.execute("""
        INSERT INTO user_sessions (user_id, access_token, refresh_token, csrf_access_token, csrf_refresh_token, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (user_id, access_token, refresh_token, csrf_access_token, csrf_refresh_token, expires_at))

    # Commit the transaction and close the connection
    conn.commit()
    cursor.close()
    conn.close()
