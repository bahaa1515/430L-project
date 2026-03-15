import React, { useState, useEffect, useContext } from 'react';
import ProofPanel from '../components/ProofPanel';
import ExchangeRateCard from '../components/ExchangeRateCard';
import TransactionsTable from '../components/TransactionsTable';
import ErrorAlert from '../components/ErrorAlert';
import apiClient from '../api/apiClient';
import { AuthContext } from '../context/AuthContext';

const DashboardPage = () => {
  const { preferences } = useContext(AuthContext);
  const [exchangeRate, setExchangeRate] = useState(null);
  const [transactions, setTransactions] = useState([]);
  const [loadingRate, setLoadingRate] = useState(false);
  const [loadingTransactions, setLoadingTransactions] = useState(false);
  const [errorRate, setErrorRate] = useState('');
  const [errorTransactions, setErrorTransactions] = useState('');

  // Analytics states
  const [analytics, setAnalytics] = useState(null);
  const [loadingAnalytics, setLoadingAnalytics] = useState(false);
  const [errorAnalytics, setErrorAnalytics] = useState('');
  const [fromDate, setFromDate] = useState(() => {
    const now = new Date();
    const from = new Date(now.getTime() - 72 * 60 * 60 * 1000);
    return from.toISOString().slice(0, 16);
  });
  const [toDate, setToDate] = useState(() => {
    const now = new Date();
    return now.toISOString().slice(0, 16);
  });

  // Insights states
  const [insights, setInsights] = useState(null);

  useEffect(() => {
    if (preferences && preferences.default_range_hours) {
      const now = new Date();
      const from = new Date(now.getTime() - preferences.default_range_hours * 60 * 60 * 1000);
      setFromDate(from.toISOString().slice(0, 16));
      setToDate(now.toISOString().slice(0, 16));
    }
    fetchExchangeRate();
    fetchTransactions();
    fetchAnalytics();
  }, [preferences]);

  useEffect(() => {
    fetchInsights();
  }, [analytics]);

  const fetchExchangeRate = async () => {
    try {
      setLoadingRate(true);
      setErrorRate('');
      const response = await apiClient.get('/exchangeRate');
      setExchangeRate(response.data.rate || response.data);
    } catch (err) {
      const statusCode = err.response?.status;
      if (statusCode === 429) {
        setErrorRate('Rate limit reached. Please try again later.');
      } else if (statusCode === 401) {
        setErrorRate('Invalid token. Please login again.');
      } else if (statusCode === 403) {
        setErrorRate('Forbidden. Your account may be suspended.');
      } else {
        setErrorRate('Failed to fetch exchange rate');
      }
    } finally {
      setLoadingRate(false);
    }
  };

  const fetchTransactions = async () => {
    try {
      setLoadingTransactions(true);
      setErrorTransactions('');
      const response = await apiClient.get('/transactions');
      setTransactions(Array.isArray(response.data) ? response.data : response.data.transactions || []);
    } catch (err) {
      const statusCode = err.response?.status;
      if (statusCode === 429) {
        setErrorTransactions('Rate limit reached. Please try again later.');
      } else if (statusCode === 401) {
        setErrorTransactions('Invalid token. Please login again.');
      } else if (statusCode === 403) {
        setErrorTransactions('Forbidden. Your account may be suspended.');
      } else {
        setErrorTransactions('Failed to fetch transactions');
      }
    } finally {
      setLoadingTransactions(false);
    }
  };

  const fetchAnalytics = async () => {
    try {
      setLoadingAnalytics(true);
      setErrorAnalytics('');
      const params = {
        direction: 'usd_to_lbp',
      };

      if (fromDate) params.from = fromDate;
      if (toDate) params.to = toDate;
      const response = await apiClient.get('/analytics/exchange-rate', { params });
      setAnalytics(response.data);
    } catch (err) {
      const statusCode = err.response?.status;
      const backendMessage = err.response?.data?.error;

      if (statusCode === 429) {
        setErrorAnalytics('Rate limit reached. Please try again later.');
      } else if (statusCode === 404) {
        setErrorAnalytics('No analytics yet. Create some transactions first.');
      } else if (statusCode === 400 && backendMessage) {
        setErrorAnalytics(backendMessage);
      } else if (backendMessage) {
        setErrorAnalytics(backendMessage);
      } else {
        setErrorAnalytics('Failed to fetch analytics');
      }

      setAnalytics(null);
    } finally {
      setLoadingAnalytics(false);
    }
  };

  const fetchInsights = async () => {
    // Assuming insights are part of analytics or separate endpoint
    // For now, set insights from analytics if available
    if (analytics) {
      setInsights({
        trend: analytics.percentage_change > 0 ? 'Increasing' : 'Decreasing',
        volatility: 'Medium', // Placeholder, calculate if possible
        biggestSpike: analytics.max_rate - analytics.min_rate,
      });
    }
  };

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '20px' }}>
      <ProofPanel />

      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ fontSize: '32px', marginBottom: '8px', color: '#2c3e50' }}>Dashboard</h1>
        <p style={{ color: '#7f8c8d', marginBottom: '24px' }}>
          Welcome to your exchange rate and transaction dashboard
        </p>
      </div>

      <div style={{ marginBottom: '32px' }}>
        <h2 style={{ fontSize: '20px', marginBottom: '16px', color: '#2c3e50' }}>Exchange Rate</h2>
        <ExchangeRateCard rate={exchangeRate} loading={loadingRate} error={errorRate} />
        <button
          onClick={fetchExchangeRate}
          disabled={loadingRate}
          style={{
            marginTop: '12px',
            padding: '8px 16px',
            backgroundColor: '#3498db',
            color: '#fff',
            border: 'none',
            borderRadius: '4px',
            cursor: loadingRate ? 'not-allowed' : 'pointer',
            fontSize: '14px',
          }}
        >
          Refresh Rate
        </button>
      </div>

      <div style={{ marginBottom: '32px' }}>
        <h2 style={{ fontSize: '20px', marginBottom: '16px', color: '#2c3e50' }}>Analytics</h2>
        <div style={{ display: 'flex', gap: '16px', marginBottom: '16px' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '4px' }}>From</label>
            <input
              type="datetime-local"
              value={fromDate}
              onChange={(e) => setFromDate(e.target.value)}
              style={{ padding: '8px', borderRadius: '4px', border: '1px solid #ccc' }}
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: '4px' }}>To</label>
            <input
              type="datetime-local"
              value={toDate}
              onChange={(e) => setToDate(e.target.value)}
              style={{ padding: '8px', borderRadius: '4px', border: '1px solid #ccc' }}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'end' }}>
            <button
              onClick={fetchAnalytics}
              disabled={loadingAnalytics}
              style={{
                padding: '8px 16px',
                backgroundColor: '#3498db',
                color: '#fff',
                border: 'none',
                borderRadius: '4px',
                cursor: loadingAnalytics ? 'not-allowed' : 'pointer',
                fontSize: '14px',
              }}
            >
              {loadingAnalytics ? 'Loading...' : 'Load Analytics'}
            </button>
          </div>
        </div>
        {errorAnalytics && <ErrorAlert message={errorAnalytics} onClose={() => setErrorAnalytics('')} />}
        {analytics && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '16px' }}>
            <div style={{ padding: '16px', border: '1px solid #ddd', borderRadius: '8px' }}>
              <div style={{ fontWeight: 'bold' }}>Min Rate</div>
              <div>{analytics.min_rate ? analytics.min_rate.toFixed(4) : '-'}</div>
            </div>
            <div style={{ padding: '16px', border: '1px solid #ddd', borderRadius: '8px' }}>
              <div style={{ fontWeight: 'bold' }}>Max Rate</div>
              <div>{analytics.max_rate ? analytics.max_rate.toFixed(4) : '-'}</div>
            </div>
            <div style={{ padding: '16px', border: '1px solid #ddd', borderRadius: '8px' }}>
              <div style={{ fontWeight: 'bold' }}>Average Rate</div>
              <div>{analytics.avg_rate ? analytics.avg_rate.toFixed(4) : '-'}</div>
            </div>
            <div style={{ padding: '16px', border: '1px solid #ddd', borderRadius: '8px' }}>
              <div style={{ fontWeight: 'bold' }}>Percentage Change</div>
              <div>{analytics.percentage_change ? `${analytics.percentage_change.toFixed(2)}%` : '-'}</div>
            </div>
          </div>
        )}
      </div>

      <div style={{ marginBottom: '32px' }}>
        <h2 style={{ fontSize: '20px', marginBottom: '16px', color: '#2c3e50' }}>Insights</h2>
        {insights && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
            <div style={{ padding: '16px', border: '1px solid #ddd', borderRadius: '8px' }}>
              <div style={{ fontWeight: 'bold' }}>Trend Summary</div>
              <div>{insights.trend}</div>
            </div>
            <div style={{ padding: '16px', border: '1px solid #ddd', borderRadius: '8px' }}>
              <div style={{ fontWeight: 'bold' }}>Volatility</div>
              <div>{insights.volatility}</div>
            </div>
            <div style={{ padding: '16px', border: '1px solid #ddd', borderRadius: '8px' }}>
              <div style={{ fontWeight: 'bold' }}>Biggest Spike</div>
              <div>{insights.biggestSpike ? insights.biggestSpike.toFixed(4) : '-'}</div>
            </div>
          </div>
        )}
      </div>

      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h2 style={{ fontSize: '20px', color: '#2c3e50', margin: 0 }}>Recent Transactions</h2>
          <button
            onClick={fetchTransactions}
            disabled={loadingTransactions}
            style={{
              padding: '8px 16px',
              backgroundColor: '#3498db',
              color: '#fff',
              border: 'none',
              borderRadius: '4px',
              cursor: loadingTransactions ? 'not-allowed' : 'pointer',
              fontSize: '14px',
            }}
          >
            Refresh
          </button>
        </div>
        <TransactionsTable
          transactions={transactions}
          loading={loadingTransactions}
          error={errorTransactions}
        />
      </div>
    </div>
  );
};

export default DashboardPage;
