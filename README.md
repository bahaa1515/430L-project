# Exchange Rate System Frontend

This is the React frontend for the Exchange Rate System project. It provides a user interface for authentication, viewing exchange rate data, creating transactions, managing marketplace offers, and accessing user and admin features based on role.

## Repository

GitHub repository: https://github.com/bahaa1515/430L-project.git

## Tech Stack

- React
- React Router
- Axios
- Recharts

## Prerequisites

Before running the project, make sure you have:

- Node.js 16 or higher
- npm
- The backend server running and accessible

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/bahaa1515/430L-project.git
   cd 430L-project

Install dependencies:

npm install
Running the Application

Start the development server:

npm start

Then open:

http://localhost:3000/bahaa-hamdan

All frontend routes use the fixed prefix:

/bahaa-hamdan
Backend Requirements

This frontend depends on the backend API being available. The backend should support the endpoints used by the frontend, including authentication, exchange rate history, analytics, transactions, marketplace actions, preferences, alerts, watchlist, notifications, and admin operations.

Make sure the API base URL in the frontend is configured correctly before running the app.

Main Pages

Login / Register: User authentication

Dashboard: Main overview page with exchange rate insights and analytics

Transactions: Create and view personal exchange transactions

History: View historical exchange rate data with charts and filtering

Marketplace: Create, browse, accept, and cancel exchange offers

Alerts: Manage exchange rate alerts

Watchlist: Track selected items

Notifications: View system notifications

Preferences: Manage user settings

Admin: Admin-only area for system monitoring and management

Main Features

Fixed slug-based routing using /bahaa-hamdan

JWT-based authentication

Protected routes for authenticated users

Role-based visibility for admin pages

Exchange rate history and analytics

Interactive charts for historical data

Transaction creation and listing

Marketplace offer management

Alerts, watchlist, notifications, and preferences support

Error handling for invalid requests and rate-limited responses

Authentication

JWT tokens are stored in localStorage and used for authenticated API requests. Protected pages require a valid login session.

Routing

The application uses a fixed slug route structure. Example routes include:

/bahaa-hamdan/login

/bahaa-hamdan/register

/bahaa-hamdan/dashboard

/bahaa-hamdan/transactions

/bahaa-hamdan/history

/bahaa-hamdan/marketplace

/bahaa-hamdan/alerts

/bahaa-hamdan/watchlist

/bahaa-hamdan/notifications

/bahaa-hamdan/preferences

/bahaa-hamdan/admin

Project Structure
src/
  api/
  components/
  context/
  pages/
  routes/
  utils/
Available Scripts

In the project directory, you can run:

npm start
npm test
npm run build
Build for Production
npm run build

This creates an optimized production build in the build folder.

Notes

All routes are prefixed with /bahaa-hamdan

Admin page access should only appear for users with the ADMIN role

The frontend expects the backend API to be running before use

Some features depend on backend permissions and available endpoints

JWT tokens are stored locally for session persistence

Sprint 2 Scope

This Sprint 2 frontend includes the main user-facing pages required for the exchange rate system, including authentication, dashboard analytics, history visualization, transactions, marketplace flow, alerts, watchlist, notifications, preferences, and role-based admin access, while preserving the existing routing structure and previously working functionality.
