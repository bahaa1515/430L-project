import React, { useState, useEffect } from 'react';
import ProofPanel from '../components/ProofPanel';
import TransactionsTable from '../components/TransactionsTable';
import ErrorAlert from '../components/ErrorAlert';
import apiClient from '../api/apiClient';

const TransactionsPage = () => {
  const [transactions, setTransactions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [rateLimitMessage, setRateLimitMessage] = useState('');

  const [formData, setFormData] = useState({
    usd_amount: '',
    lbp_amount: '',
    usd_to_lbp: true,
  });
  const [submitting, setSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const [formError, setFormError] = useState('');

  // Cooldown for create transaction
  const [createCooldown, setCreateCooldown] = useState(false);
  const [createCountdown, setCreateCountdown] = useState(0);

  // New state for export
  const [exporting, setExporting] = useState(false);

  // Export endpoint constant (adjust if backend differs)
  const EXPORT_ENDPOINT = '/transactions/export';

  useEffect(() => {
    fetchTransactions();
  }, []);

  const fetchTransactions = async () => {
    try {
      setLoading(true);
      setError('');
      setRateLimitMessage('');

      const response = await apiClient.get('/transactions');
      setTransactions(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      const statusCode = err.response?.status;

      if (statusCode === 429) {
        setRateLimitMessage('Rate limit reached. Please wait before fetching again.');
        setError('Too many requests');
      } else if (statusCode === 401) {
        setError('Invalid token. Please login again.');
      } else if (statusCode === 403) {
        setError('Forbidden. Your account may be suspended.');
      } else {
        setError(err.response?.data?.error || 'Failed to fetch transactions');
      }
    } finally {
      setLoading(false);
    }
  };

const handleExport = async () => {
  try {
    setExporting(true);
    setError('');

    const response = await apiClient.get(EXPORT_ENDPOINT, {
      responseType: 'blob',
    });

    const blob = new Blob([response.data], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);

    const contentDisposition = response.headers['content-disposition'];
    let filename = 'transactions.csv';

    if (contentDisposition) {
      const match = contentDisposition.match(/filename="?([^"]+)"?/);
      if (match && match[1]) {
        filename = match[1];
      }
    }

    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    window.URL.revokeObjectURL(url);
  } catch (err) {
    setError(err.response?.data?.error || 'Failed to export transactions');
  } finally {
    setExporting(false);
  }
};

  const handleFormChange = (e) => {
    const { name, value } = e.target;

    if (name === 'usd_to_lbp') {
      setFormData((prev) => ({
        ...prev,
        usd_to_lbp: value === 'true',
      }));
      return;
    }

    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormError('');
    setSuccessMessage('');

    const usdAmount = parseFloat(formData.usd_amount);
    const lbpAmount = parseFloat(formData.lbp_amount);

    if (
      formData.usd_amount === '' ||
      formData.lbp_amount === '' ||
      typeof formData.usd_to_lbp !== 'boolean'
    ) {
      setFormError('All fields are required');
      return;
    }

    if (isNaN(usdAmount) || isNaN(lbpAmount)) {
      setFormError('Amounts must be numbers');
      return;
    }

    if (usdAmount <= 0 || lbpAmount <= 0) {
      setFormError('Amounts must be positive numbers');
      return;
    }

    try {
      setSubmitting(true);

      await apiClient.post('/transaction', {
        usd_amount: usdAmount,
        lbp_amount: lbpAmount,
        usd_to_lbp: formData.usd_to_lbp,
      });

      setSuccessMessage('Transaction created successfully');
      setFormData({
        usd_amount: '',
        lbp_amount: '',
        usd_to_lbp: true,
      });

      await fetchTransactions();
    } catch (err) {
      if (err.response?.status === 429) {
        setFormError('Too many requests. Please wait before creating another transaction.');
        startCreateCooldown(15); // 15 seconds cooldown
      } else {
        setFormError(err.response?.data?.error || 'Failed to create transaction');
      }
    } finally {
      setSubmitting(false);
    }
  };

  const startCreateCooldown = (seconds) => {
    setCreateCooldown(true);
    setCreateCountdown(seconds);
    const interval = setInterval(() => {
      setCreateCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(interval);
          setCreateCooldown(false);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
  };

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '20px' }}>
      <ProofPanel />

      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ fontSize: '32px', marginBottom: '8px', color: '#2c3e50' }}>
          Transactions
        </h1>
        <p style={{ color: '#7f8c8d', marginBottom: '24px' }}>
          View all your transactions and create new ones
        </p>
      </div>

      <div
        style={{
          marginBottom: '32px',
          padding: '20px',
          border: '1px solid #ddd',
          borderRadius: '8px',
          backgroundColor: '#fff',
        }}
      >
        <h2 style={{ fontSize: '24px', marginBottom: '16px' }}>
          Create New Transaction
        </h2>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', marginBottom: '4px' }}>USD Amount:</label>
            <input
              type="number"
              name="usd_amount"
              value={formData.usd_amount}
              onChange={handleFormChange}
              step="0.01"
              min="0.01"
              required
              style={{
                width: '100%',
                padding: '8px',
                border: '1px solid #ccc',
                borderRadius: '4px',
              }}
            />
          </div>

          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', marginBottom: '4px' }}>LBP Amount:</label>
            <input
              type="number"
              name="lbp_amount"
              value={formData.lbp_amount}
              onChange={handleFormChange}
              step="0.01"
              min="0.01"
              required
              style={{
                width: '100%',
                padding: '8px',
                border: '1px solid #ccc',
                borderRadius: '4px',
              }}
            />
          </div>

          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', marginBottom: '4px' }}>Direction:</label>
            <select
              name="usd_to_lbp"
              value={String(formData.usd_to_lbp)}
              onChange={handleFormChange}
              style={{
                width: '100%',
                padding: '8px',
                border: '1px solid #ccc',
                borderRadius: '4px',
              }}
            >
              <option value="true">USD to LBP</option>
              <option value="false">LBP to USD</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={submitting || createCooldown}
            style={{
              padding: '10px 20px',
              backgroundColor: (submitting || createCooldown) ? '#95a5a6' : '#27ae60',
              color: '#fff',
              border: 'none',
              borderRadius: '4px',
              cursor: (submitting || createCooldown) ? 'not-allowed' : 'pointer',
              fontSize: '14px',
              fontWeight: 'bold',
            }}
          >
            {submitting ? 'Creating...' : createCooldown ? `Try again in ${createCountdown}s` : 'Create Transaction'}
          </button>
        </form>

        {formError && <ErrorAlert message={formError} onClose={() => setFormError('')} />}

        {successMessage && (
          <div
            style={{
              marginTop: '16px',
              padding: '10px',
              backgroundColor: '#d4edda',
              color: '#155724',
              borderRadius: '4px',
            }}
          >
            {successMessage}
          </div>
        )}
      </div>

      {rateLimitMessage && (
        <ErrorAlert message={rateLimitMessage} onClose={() => setRateLimitMessage('')} />
      )}

      {error && <ErrorAlert message={error} onClose={() => setError('')} />}

      <div style={{ marginBottom: '16px' }}>
        <button
          onClick={fetchTransactions}
          disabled={loading}
          style={{
            padding: '10px 20px',
            backgroundColor: '#3498db',
            color: '#fff',
            border: 'none',
            borderRadius: '4px',
            cursor: loading ? 'not-allowed' : 'pointer',
            fontSize: '14px',
            fontWeight: 'bold',
            marginRight: '10px',
          }}
        >
          {loading ? 'Loading...' : 'Refresh Transactions'}
        </button>
        <button
          onClick={handleExport}
          disabled={exporting}
          style={{
            padding: '10px 20px',
            backgroundColor: '#e67e22',
            color: '#fff',
            border: 'none',
            borderRadius: '4px',
            cursor: exporting ? 'not-allowed' : 'pointer',
            fontSize: '14px',
            fontWeight: 'bold',
          }}
        >
          {exporting ? 'Exporting...' : 'Export CSV'}
        </button>
      </div>

      <TransactionsTable
        transactions={transactions}
        loading={loading}
        error={error}
      />
    </div>
  );
};

export default TransactionsPage;