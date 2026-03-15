// src/components/Navbar.jsx

import React, { useContext } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import { getRoute, ROUTES } from '../utils/routeHelper';

const styles = {
  wrapper: {
    padding: '20px 24px 0 24px',
  },
  nav: {
    backgroundColor: '#ffffff',
    border: '1px solid #dee2e6',
    borderRadius: '14px',
    padding: '14px 18px',
    boxShadow: '0 2px 8px rgba(0,0,0,0.04)',
    marginBottom: '8px',
  },
  row: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: '16px',
    flexWrap: 'wrap',
  },
  links: {
    listStyle: 'none',
    display: 'flex',
    gap: '10px',
    margin: 0,
    padding: 0,
    flexWrap: 'wrap',
    alignItems: 'center',
  },
  link: {
    display: 'inline-block',
    padding: '10px 14px',
    borderRadius: '10px',
    textDecoration: 'none',
    color: '#1f3b57',
    fontWeight: '600',
    transition: '0.2s ease',
    border: '1px solid transparent',
  },
  activeLink: {
    backgroundColor: '#eaf4ff',
    color: '#1f3b57',
    border: '1px solid #cfe2ff',
  },
  logoutButton: {
    backgroundColor: '#dc3545',
    color: '#fff',
    border: 'none',
    borderRadius: '10px',
    padding: '10px 16px',
    fontWeight: '600',
    cursor: 'pointer',
  },
  userText: {
    color: '#6c757d',
    fontSize: '14px',
    fontWeight: '500',
  },
};

const Navbar = () => {
  const { isAuthenticated, user, logout } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate(getRoute(ROUTES.LOGIN), { replace: true });
  };

  if (!isAuthenticated) {
    return null;
  }

  const navItems = [
    { label: 'Dashboard', path: getRoute(ROUTES.DASHBOARD) },
    { label: 'Transactions', path: getRoute(ROUTES.TRANSACTIONS) },
    { label: 'History', path: getRoute(ROUTES.HISTORY) },
    { label: 'Marketplace', path: getRoute(ROUTES.MARKETPLACE) },
    { label: 'Alerts', path: getRoute(ROUTES.ALERTS) },
    { label: 'Watchlist', path: getRoute(ROUTES.WATCHLIST) },
    { label: 'Notifications', path: getRoute(ROUTES.NOTIFICATIONS) },
    { label: 'Preferences', path: getRoute(ROUTES.PREFERENCES) },
  ];

  if (String(user?.role || '').toUpperCase() === 'ADMIN') {
    navItems.push({ label: 'Admin', path: getRoute(ROUTES.ADMIN) });
  }

  return (
    <div style={styles.wrapper}>
      <nav style={styles.nav}>
        <div style={styles.row}>
          <ul style={styles.links}>
            {navItems.map((item) => (
              <li key={item.path}>
                <NavLink
                  to={item.path}
                  style={({ isActive }) => ({
                    ...styles.link,
                    ...(isActive ? styles.activeLink : {}),
                  })}
                >
                  {item.label}
                </NavLink>
              </li>
            ))}
          </ul>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            {user?.full_name && (
              <span style={styles.userText}>Signed in as {user.full_name}</span>
            )}
            <button type="button" onClick={handleLogout} style={styles.logoutButton}>
              Logout
            </button>
          </div>
        </div>
      </nav>
    </div>
  );
};

export default Navbar;