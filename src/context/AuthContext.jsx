// src/context/AuthContext.jsx

import React, { createContext, useContext, useEffect, useState } from 'react';
import apiClient from '../api/apiClient';

export const AuthContext = createContext();

export const useAuth = () => useContext(AuthContext);

const getErrorMessage = (error, fallback) => {
  return (
    error?.response?.data?.error ||
    error?.response?.data?.message ||
    error?.response?.data?.msg ||
    fallback
  );
};

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [userId, setUserId] = useState(null);
  const [user, setUser] = useState(null);
  const [preferences, setPreferences] = useState(null);

const fetchUser = async () => {
  try {
    const response = await apiClient.get('/whoami');
    const data = response.data || {};

    const normalizedUser = {
      ...data,
      user_id: data.user_id ?? data.id ?? null,
      full_name: data.full_name ?? data.name ?? '',
      role: String(data.role ?? data.user?.role ?? '').toUpperCase(),
    };

    setUserId(normalizedUser.user_id);
    setUser(normalizedUser);
    setIsAuthenticated(true);

    await loadPreferences();
    return normalizedUser.user_id;
  } catch (err) {
    setUserId(null);
    setUser(null);
    setIsAuthenticated(false);
    return null;
  }
};

  const loadPreferences = async () => {
    try {
      const response = await apiClient.get('/preferences');
      setPreferences(response.data || {});
    } catch (err) {
      setPreferences({});
    }
  };

  const register = async (userData) => {
    setError(null);
    try {
      const response = await apiClient.post('/user', userData);
      return { success: true, data: response.data };
    } catch (err) {
      const message = getErrorMessage(err, 'Registration failed');
      setError(message);
      return { success: false, error: message };
    }
  };

  const login = async (credentials) => {
    setError(null);
    try {
      const response = await apiClient.post('/login', credentials);

      if (response.data.access_token) {
        localStorage.setItem('access_token', response.data.access_token);
      }
      if (response.data.refresh_token) {
        localStorage.setItem('refresh_token', response.data.refresh_token);
      }

    await fetchUser();
    return { success: true, data: response.data };
    } catch (err) {
      const message = getErrorMessage(err, 'Login failed');
      setError(message);
      setIsAuthenticated(false);
      setUserId(null);
      return { success: false, error: message, status: err.response?.status };
    }
  };

const logout = async () => {
  try {
    await apiClient.post('/logout');
  } catch (err) {
    // ignore logout API failure and still clear local state
  }

  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  setIsAuthenticated(false);
  setUserId(null);
  setUser(null);
  setPreferences(null);
  setError(null);
};

  useEffect(() => {
    const token = localStorage.getItem('access_token');

    const initAuth = async () => {
      if (!token) {
        setLoading(false);
        return;
      }

      await fetchUser();
      setLoading(false);
    };

    initAuth();
  }, []);

  return (
    <AuthContext.Provider
      value={{
        register,
        login,
        logout,
        isAuthenticated,
        loading,
        error,
        userId,
        user,
        preferences,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};