// src/App.jsx

import React, { useContext } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, AuthContext } from './context/AuthContext';
import ProtectedRoute from './routes/ProtectedRoute';
import Navbar from './components/Navbar';
import { FIXED_SLUG, getRoute, ROUTES } from './utils/routeHelper';

import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import TransactionsPage from './pages/TransactionsPage';
import HistoryPage from './pages/HistoryPage';
import MarketplacePage from './pages/MarketplacePage';
import AlertsPage from './pages/AlertsPage';
import WatchlistPage from './pages/WatchlistPage';
import NotificationsPage from './pages/NotificationsPage';
import PreferencesPage from './pages/PreferencesPage';
import AdminPage from './pages/AdminPage';
const PlaceholderPage = ({ title }) => (
  <div style={{ padding: '24px' }}>
    <h1>{title}</h1>
    <p>Coming soon...</p>
  </div>
);

function AppRoutes() {
  const { isAuthenticated, loading } = useContext(AuthContext);

  if (loading) {
    return <div style={{ padding: '24px' }}>Loading...</div>;
  }

  return (
    <>
      <Navbar />
      <Routes>
        <Route
          path="/"
          element={
            <Navigate
              to={isAuthenticated ? getRoute(ROUTES.DASHBOARD) : getRoute(ROUTES.LOGIN)}
              replace
            />
          }
        />

        <Route path={`/${FIXED_SLUG}/login`} element={<LoginPage />} />
        <Route path={`/${FIXED_SLUG}/register`} element={<RegisterPage />} />

        <Route
          path={`/${FIXED_SLUG}/dashboard`}
          element={
            <ProtectedRoute>
              <DashboardPage />
            </ProtectedRoute>
          }
        />

        <Route
          path={`/${FIXED_SLUG}/transactions`}
          element={
            <ProtectedRoute>
              <TransactionsPage />
            </ProtectedRoute>
          }
        />

        <Route
          path={getRoute(ROUTES.HISTORY)}
          element={
            <ProtectedRoute>
              <HistoryPage />
            </ProtectedRoute>
          }
        />

        <Route
          path={getRoute(ROUTES.MARKETPLACE)}
          element={
            <ProtectedRoute>
              <MarketplacePage />
            </ProtectedRoute>
          }
        />

        <Route
          path={getRoute(ROUTES.ALERTS)}
          element={
            <ProtectedRoute>
              <AlertsPage />
            </ProtectedRoute>
          }
        />

        <Route
          path={getRoute(ROUTES.WATCHLIST)}
          element={
            <ProtectedRoute>
              <WatchlistPage />
            </ProtectedRoute>
          }
        />

        <Route
          path={getRoute(ROUTES.NOTIFICATIONS)}
          element={
            <ProtectedRoute>
              <NotificationsPage />
            </ProtectedRoute>
          }
        />

        <Route
          path={getRoute(ROUTES.PREFERENCES)}
          element={
            <ProtectedRoute>
              <PreferencesPage />
            </ProtectedRoute>
          }
        />

        <Route
          path={getRoute(ROUTES.ADMIN)}
          element={
            <ProtectedRoute>
              <AdminPage />
            </ProtectedRoute>
          }
        />

        <Route
          path="*"
          element={
            <Navigate
              to={isAuthenticated ? getRoute(ROUTES.DASHBOARD) : getRoute(ROUTES.LOGIN)}
              replace
            />
          }
        />
      </Routes>
    </>
  );
}

function App() {
  return (
    <AuthProvider>
      <Router>
        <AppRoutes />
      </Router>
    </AuthProvider>
  );
}

export default App;