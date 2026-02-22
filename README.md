Exchange Rate & P2P Marketplace Backend
Overview

This project implements a secure backend system for tracking currency exchange rates, performing real-time currency exchange transactions, and supporting a peer-to-peer (P2P) exchange marketplace. The backend exposes RESTful APIs that allow users to authenticate, manage balances, analyze exchange rates, configure alerts and preferences, and receive system notifications. Administrative features such as role-based access control, audit logging, rate limiting, and backups are also supported.

The system is designed following DevSecOps principles, emphasizing security, traceability, and reliability.

Technologies Used

Python 3

Flask

Flask-SQLAlchemy

Flask-JWT-Extended

Flask-Limiter

Flask-Migrate

MySQL

SQLAlchemy

Marshmallow

bcrypt

python-dotenv

Project Structure
project/
│
├── app.py                 # Main Flask application (routes, models, logic)
├── migrations/            # Database migrations (Flask-Migrate)
├── backups/               # Generated database backup files
├── .env                   # Environment variables (not committed)
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation
Environment Configuration

Create a .env file in the project root directory with the following variables:

DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=exchange

JWT_SECRET_KEY=your_secret_key
How to Run the Backend
1. Create and Activate a Virtual Environment
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
2. Install Dependencies
pip install -r requirements.txt
3. Initialize the Database
flask db init
flask db migrate
flask db upgrade
4. Run the Server
flask run

The backend will start on:

http://127.0.0.1:5000
Authentication Flow

A user account is created using POST /user

The user logs in using POST /login

The backend returns:

Access token (short-lived)

Refresh token

Protected endpoints require the access token in the request header:

Authorization: Bearer <access_token>
Core Backend Features
1. Exchange Rate Analytics

Computes minimum, maximum, average exchange rates

Calculates percentage change over a time range

Supports user-defined or default date ranges

2. Exchange Rate History (Time-Series)

Returns bucketed exchange-rate data (hour or day)

Designed for frontend graph visualization

3. Transactions

Real-time balance validation

Atomic balance updates

Automatic implied exchange-rate computation

Outlier detection to block anomalous rates

4. P2P Exchange Marketplace

Users can create exchange offers

View open offers from other users

Cancel their own offers

Trades are recorded and tracked

5. Exchange Rate Alerts

Users define threshold-based alerts

Alerts trigger automatically when conditions are met

Alerts are triggered once to prevent spamming

6. Watchlist / Favorites

Users track preferred exchange directions or thresholds

Used for monitoring without constant queries

7. Transaction Export (CSV)

Users can export their transaction history

CSV includes amounts, direction, and timestamps

8. User Preferences Service

Stores default time range and bucket size

Automatically applied when query parameters are omitted

9. Admin & Moderation (RBAC)

Role-based access control:

USER

ADMIN

Admins can perform privileged operations

Sensitive actions require fresh tokens

10. Audit Logging & Compliance Tracking

Logs all critical actions:

Authentication attempts

Transactions

Marketplace operations

Admin actions

Logs include timestamps, actor, action, and result

11. Notifications Service

System-generated notifications for key events

Stored persistently

Can be marked as read

Duplicate notifications are prevented

12. Data Quality & Integrity

Tracks exchange-rate sources

Detects anomalous rates using statistical methods

Marks outliers for transparency

13. Rate Limiting

Protects critical endpoints (login, transactions, marketplace)

Prevents brute-force and abuse

14. Consolidated Reporting

Aggregates transaction and exchange-rate data

Used by analytics and export services

15. Data Migration & Backups

Admin-triggered database backups

Stored as structured JSON files

Supports full restore operations

16. Security & Validation

JWT authentication

Role-based authorization

Input validation on all endpoints

Secure password hashing

Sanitized error responses


Testing the Backend

All endpoints can be tested using Postman:

Create a user

Login and store tokens

Add transactions

Retrieve analytics and history

Create marketplace offers

Configure alerts and watchlist

Verify notifications and logs
