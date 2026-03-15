import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import ErrorAlert from '../components/ErrorAlert';
import { getRoute, ROUTES } from '../utils/routeHelper';
import ProofPanel from '../components/ProofPanel';

const LoginPage = () => {
  const [userName, setUserName] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState('');
  const [cooldown, setCooldown] = useState(false);
  const [countdown, setCountdown] = useState(0);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLocalError('');

    if (!userName.trim() || !password.trim()) {
      setLocalError('Username and password are required');
      return;
    }

    setLoading(true);
    const result = await login({
      user_name: userName,
      password: password,
    });
    setLoading(false);

    if (result.success) {
      navigate(getRoute(ROUTES.DASHBOARD));
    } else {
      if (result.status === 429) {
        setLocalError('Too many login attempts. Please wait before trying again.');
        startCooldown(30); // 30 seconds cooldown
      } else {
        setLocalError(result.error || 'Login failed');
      }
    }
  };

  const startCooldown = (seconds) => {
    setCooldown(true);
    setCountdown(seconds);
    const interval = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(interval);
          setCooldown(false);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
  };

  return (
    <div style={{ maxWidth: '600px', margin: '0 auto', padding: '20px' }}>
      <ProofPanel />

      <div
        style={{
          backgroundColor: '#fff',
          padding: '32px',
          borderRadius: '8px',
          boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
        }}
      >
        <h1 style={{ fontSize: '28px', marginBottom: '8px', color: '#2c3e50' }}>Login</h1>
        <p style={{ color: '#7f8c8d', marginBottom: '24px' }}>
          Sign in to your account
        </p>

        {localError && <ErrorAlert message={localError} onClose={() => setLocalError('')} />}

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '16px' }}>
            <label
              style={{
                display: 'block',
                marginBottom: '8px',
                fontWeight: 'bold',
                color: '#2c3e50',
              }}
            >
              Username
            </label>
            <input
              type="text"
              value={userName}
              onChange={(e) => setUserName(e.target.value)}
              disabled={loading}
              style={{
                width: '100%',
                padding: '10px 12px',
                border: '1px solid #bdc3c7',
                borderRadius: '4px',
                fontSize: '14px',
                boxSizing: 'border-box',
                opacity: loading ? 0.7 : 1,
              }}
              placeholder="Enter your username"
            />
          </div>

          <div style={{ marginBottom: '24px' }}>
            <label
              style={{
                display: 'block',
                marginBottom: '8px',
                fontWeight: 'bold',
                color: '#2c3e50',
              }}
            >
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading}
              style={{
                width: '100%',
                padding: '10px 12px',
                border: '1px solid #bdc3c7',
                borderRadius: '4px',
                fontSize: '14px',
                boxSizing: 'border-box',
                opacity: loading ? 0.7 : 1,
              }}
              placeholder="Enter your password"
            />
          </div>

          <button
            type="submit"
            disabled={loading || cooldown}
            style={{
              width: '100%',
              padding: '12px',
              backgroundColor: (loading || cooldown) ? '#95a5a6' : '#3498db',
              color: '#fff',
              border: 'none',
              borderRadius: '4px',
              fontSize: '16px',
              fontWeight: 'bold',
              cursor: (loading || cooldown) ? 'not-allowed' : 'pointer',
              transition: 'background-color 0.3s',
            }}
          >
            {loading ? 'Logging in...' : cooldown ? `Try again in ${countdown}s` : 'Login'}
          </button>
        </form>

        <p style={{ marginTop: '24px', textAlign: 'center', color: '#7f8c8d' }}>
          Don't have an account?{' '}
          <Link
            to={getRoute(ROUTES.REGISTER)}
            style={{ color: '#3498db', textDecoration: 'none', fontWeight: 'bold' }}
          >
            Register here
          </Link>
        </p>
      </div>
    </div>
  );
};

export default LoginPage;
