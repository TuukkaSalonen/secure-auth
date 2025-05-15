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

**You should set your own environment variables in the backend root .env file even though some default ones are set.**

##### Required

- DATABASE_URL (**required**, Url for the Postgres database. E.g. ``postgresql://host:port/database``)

##### Required for OAuth login
- GITHUB_CLIENT_ID (**required** for GitHub OAuth)
- GITHUB_CLIENT_SECRET (**required** for GitHub OAuth)

- GOOGLE_CLIENT_ID (**required** for Google OAuth)
- GOOGLE_CLIENT_SECRET (**required** for Google OAuth)

##### Has default but should **change**
- GOOGLE_REDIRECT_URI (``http://localhost:5000/api/login/google/callback`` as **default** update if port is changed)
- GITHUB_REDIRECT_URI (``http://localhost:5000/api/login/github/callback`` as **default** update if port is changed)

- FRONTEND_URL (``http://localhost:5173`` as **default**, update if port is changed)

- MASTER_KEY (``Gkqv9Zx8T9W2X3Y4Z5a6b7c8d9e0f1g2h3i4j5k6l7m=`` as **default**, needs to be 32byte url-safe base4 encoded for user key encryption)
- SECRET_KEY (``secret-key`` as **default** for Flask)
- JWT_SECRET_KEY (``jwt-secret-key`` as **default** for Flask-JWT-Extended)
- ENCRYPTION_KEY_MFA (``Gkqv9Zx8T9W2X3Y4Z5a6b7c8d9e0f1g2h3i4j5k6l7m=`` as **default**, needs to be 32byte url-safe base4 encoded for user MFA key encryption)

- PREFERRED_URL_SCHEME (``http`` as **default**)

- LOG_FILE (`./app/logs/app.log` as **default** for log file location, change if you wish)
- BACKUP_DIR (``./app/backups`` as **default** for db backup directory, change if you wish)

## Running the application

### Development environment with hot-reload
In the root directory, run `npm run dev` to start the application in development environment. It contains a script that starts both backend and frontend concurrently. Due to the Content-Security-Policy headers, the application doesn't load on Firefox because of stricter policy and the application requiring in-line scripts in development mode.

### Built environment
In the root directory, run `npm start` to start the application. Similarly as before, both the backend and frontend are started concurrently. However, the frontend built and run in production preview environment. This allows the application to load on Firefox due to having static files. 

### Installing dependencies
You can install all the required dependencies by running `npm run install-all` in root.

### Initializing db
The migration directory already exists, but if you want your own, remove it and run `npm run db-init` in root.

To migrate, run `npm run db-migrate` in root.

And to upgrade, run `npm run db-upgrade` in root.

### Ports
The frontend runs on port `5173` and the backend on port `5000`.

## Running the tests
### All tests
In the root directory the tests for both frontend and backend can be run with `npm test`.

### Backend tests
The backend tests can be run individually in the backend directory using the command `pytest`.

### Frontend tests
The frontend tests can be run individually in the frontend directory using the command `npm test`.