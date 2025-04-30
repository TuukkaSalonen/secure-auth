# Secure Programming Project

## Application description
Register and secure login with OAuth and Authenticator (TOTP) features.\
Login with Google or GitHub account.\
Upload and download files that are encrypted in the database.\
Unit tests for served routes.

## Running the application

### Development environment
In the root directory, run `npm run dev` to start the application in development environment. It contains a script that starts both backend and frontend concurrently. Due to the Content-Security-Policy headers, the application doesn't load on Firefox because of stricter policy and the application requiring in-line scripts in development mode.

### Production preview environment
In the root directory, run `npm start` to start the frontend in production preview environment. The frontend build is created and is run in production preview environment. This allows the application to load on Firefox due to having static files. 

### Ports
The frontend runs on port `5173` and the backend on port `5000`.

## Running the tests
In the root directory the tests for both frontend and backend can be run with `npm test`.\
The backend tests can be run individually in the backend directory using the command `pytest`.\
The frontend tests can be run individually in the frontend directory using the command `npm test`.

## TODO:
Notifications\
Styling\
Add try/catch\
Check OWASP Top 10\
File type checks backend, file scans?, file name sanitize werkzeug?\
Better comments explaining security solution reasons\
Argumenting security quality in report