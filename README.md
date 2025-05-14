# Secure Programming Project

## Application description
### File storage web application

#### Features

- Upload and download files that are encrypted in the database.
- Register via username or email or login with your 
- Google or GitHub account with OAuth.
- Authenticator (TOTP) feature with cookie-based JWT authentication.
- Unit tests for served routes and frontend.
- Database backup.
- Security logging.


## Requirements 

### Used versions in development
- Python 3.13.2
- Node v20.11.1

### Environment variables (.env)

#### The following environment variables used in the application
- FRONTEND_URL (``http://localhost:5173`` as **default**, update if port is changed)
- DATABASE_URL (**required**, Url for the Postgres database)

- MASTER_KEY (**required** for user key encryption)
- SECRET_KEY (``secret-key`` as **default** for Flask)
- JWT_SECRET_KEY (``jwt-secret-key`` as **default** for Flask-JWT-Extended)
- ENCRYPTION_KEY_MFA (``encryption-key-mfa`` as **default** for user MFA key encryption)

- GOOGLE_CLIENT_ID (**required** for Google OAuth)
- GOOGLE_CLIENT_SECRET (**required** for Google OAuth)
- GOOGLE_REDIRECT_URI (``http://localhost:5000/api/login/google/callback`` as **default** update if port is changed)

- GITHUB_CLIENT_ID (**required** for GitHub OAuth)
- GITHUB_CLIENT_SECRET (**required** for GitHub OAuth)
- GITHUB_REDIRECT_URI (``http://localhost:5000/api/login/github/callback`` as **default** update if port is changed)

- PREFERRED_URL_SCHEME (``http`` as **default**)

- LOG_FILE (`./app/logs/app.log` as **default** for log file location, change if you wish)
- BACKUP_DIR (``./app/backups`` as **default** for db backup directory, change if you wish)

**You should set your own environment variables in addition to the required variables for those that have default values.**

## Running the application

### Development environment with hot-reload
In the root directory, run `npm run dev` to start the application in development environment. It contains a script that starts both backend and frontend concurrently. Due to the Content-Security-Policy headers, the application doesn't load on Firefox because of stricter policy and the application requiring in-line scripts in development mode.

### Built environment
In the root directory, run `npm start` to start the application. Similarly as before, both the backend and frontend are started concurrently. However, the frontend built and run in production preview environment. This allows the application to load on Firefox due to having static files. 

### Ports
The frontend runs on port `5173` and the backend on port `5000`.

## Running the tests
### All tests
In the root directory the tests for both frontend and backend can be run with `npm test`.

### Backend tests
The backend tests can be run individually in the backend directory using the command `pytest`.

### Frontend tests
The frontend tests can be run individually in the frontend directory using the command `npm test`.