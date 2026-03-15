// src/utils/routeHelper.js

export const FIXED_SLUG = 'bahaa-hamdan';

export const ROUTES = {
  LOGIN: '/login',
  REGISTER: '/register',
  DASHBOARD: '/dashboard',
  TRANSACTIONS: '/transactions',
  HISTORY: '/history',
  MARKETPLACE: '/marketplace',
  ALERTS: '/alerts',
  WATCHLIST: '/watchlist',
  NOTIFICATIONS: '/notifications',
  PREFERENCES: '/preferences',
  ADMIN: '/admin',
};

export const getRoute = (route) => `/${FIXED_SLUG}${route}`;