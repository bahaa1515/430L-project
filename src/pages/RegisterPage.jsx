import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import ErrorAlert from '../components/ErrorAlert';
import { getRoute, ROUTES } from '../utils/routeHelper';
import ProofPanel from '../components/ProofPanel';

const RegisterPage = () => {
  const [userName, setUserName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const { register } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLocalError('');
    setSuccessMessage('');

    // Validation
    if (!userName.trim() || !password.trim() || !confirmPassword.trim()) {
      setLocalError('All fields are required');
      return;
    }

    if (password.length < 6) {
      setLocalError('Password must be at least 6 characters');
      return;
    }

    if (password !== confirmPassword) {
      setLocalError('Passwords do not match');
      return;
    }

    setLoading(true);
    const result = await register({
      user_name: userName,
      password: password,
    });
    setLoading(false);

    if (result.success) {
      setSuccessMessage('Account created successfully! Redirecting to login...');
      setTimeout(() => {
        navigate(getRoute(ROUTES.LOGIN));
      }, 2000);
    } else {
      setLocalError(result.error || 'Registration failed');
    }
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
        <h1 style={{ fontSize: '28px', marginBottom: '8px', color: '#2c3e50' }}>Register</h1>
        <p style={{ color: '#7f8c8d', marginBottom: '24px' }}>
          Create a new account
        </p>

        {localError && <ErrorAlert message={localError} onClose={() => setLocalError('')} />}

        {successMessage && (
          <div
            style={{
              backgroundColor: '#d4edda',
              border: '1px solid #c3e6cb',
              color: '#155724',
              padding: '12px 16px',
              borderRadius: '4px',
              marginBottom: '16px',
              textAlign: 'center',
            }}
          >
            {successMessage}
          </div>
        )}

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
              placeholder="Choose a username"
            />
          </div>

          <div style={{ marginBottom: '16px' }}>
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
              placeholder="Create a password (min 6 characters)"
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
              Confirm Password
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
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
              placeholder="Confirm your password"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%',
              padding: '12px',
              backgroundColor: loading ? '#95a5a6' : '#27ae60',
              color: '#fff',
              border: 'none',
              borderRadius: '4px',
              fontSize: '16px',
              fontWeight: 'bold',
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'background-color 0.3s',
            }}
          >
            {loading ? 'Creating account...' : 'Register'}
          </button>
        </form>

        <p style={{ marginTop: '24px', textAlign: 'center', color: '#7f8c8d' }}>
          Already have an account?{' '}
          <Link
            to={getRoute(ROUTES.LOGIN)}
            style={{ color: '#3498db', textDecoration: 'none', fontWeight: 'bold' }}
          >
            Login here
          </Link>
        </p>
      </div>
    </div>
  );
};

export default RegisterPage;
