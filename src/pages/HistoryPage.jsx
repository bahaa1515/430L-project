import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import ProofPanel from '../components/ProofPanel';
import ErrorAlert from '../components/ErrorAlert';
import apiClient from '../api/apiClient';

const styles = {
  page: {
    maxWidth: '1150px',
    margin: '0 auto',
    padding: '24px',
  },
  pageHeader: {
    marginBottom: '28px',
  },
  title: {
    fontSize: '48px',
    marginBottom: '10px',
    color: '#1f3b57',
    fontWeight: '700',
  },
  subtitle: {
    color: '#7f8c8d',
    fontSize: '17px',
    margin: 0,
  },
  card: {
    marginBottom: '28px',
    padding: '28px',
    border: '1px solid #dee2e6',
    borderRadius: '14px',
    backgroundColor: '#ffffff',
    boxShadow: '0 2px 8px rgba(0,0,0,0.04)',
  },
  sectionTitle: {
    fontSize: '24px',
    marginTop: 0,
    marginBottom: '20px',
    color: '#1f3b57',
    fontWeight: '700',
  },
  controlsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
    gap: '16px',
    alignItems: 'end',
  },
  field: {
    display: 'flex',
    flexDirection: 'column',
  },
  label: {
    display: 'block',
    marginBottom: '8px',
    fontWeight: '600',
    color: '#1f3b57',
    fontSize: '15px',
  },
  input: {
    padding: '12px 14px',
    border: '1px solid #ced4da',
    borderRadius: '8px',
    fontSize: '15px',
    backgroundColor: '#fff',
  },
  button: {
    padding: '12px 22px',
    backgroundColor: '#3498db',
    color: '#fff',
    border: 'none',
    borderRadius: '8px',
    cursor: 'pointer',
    fontSize: '15px',
    fontWeight: '700',
    minHeight: '46px',
  },
  helperText: {
    marginTop: '14px',
    color: '#7f8c8d',
    fontSize: '15px',
  },
  loadingText: {
    marginBottom: '18px',
    color: '#7f8c8d',
    fontWeight: '500',
  },
  statsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '16px',
  },
  statCard: {
    backgroundColor: '#f8fafc',
    border: '1px solid #e9ecef',
    borderRadius: '12px',
    padding: '16px',
  },
  statLabel: {
    fontSize: '13px',
    color: '#6c757d',
    marginBottom: '8px',
    fontWeight: '600',
    textTransform: 'uppercase',
    letterSpacing: '0.4px',
  },
  statValue: {
    fontSize: '22px',
    color: '#1f3b57',
    fontWeight: '700',
    wordBreak: 'break-word',
  },
  statValueSmall: {
    fontSize: '16px',
    color: '#1f3b57',
    fontWeight: '600',
    wordBreak: 'break-word',
  },
  tableCard: {
    marginBottom: '28px',
  },
  tableWrapper: {
    overflowX: 'auto',
    borderRadius: '12px',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    backgroundColor: '#fff',
  },
  th: {
    backgroundColor: '#34495e',
    color: '#fff',
    textAlign: 'left',
    padding: '14px 16px',
    fontWeight: '700',
    fontSize: '15px',
  },
  td: {
    padding: '14px 16px',
    borderTop: '1px solid #e9ecef',
    fontSize: '15px',
  },
  emptyText: {
    color: '#7f8c8d',
    fontSize: '15px',
    marginTop: '8px',
  },
};

const HistoryPage = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [preferences, setPreferences] = useState(null);
  const [direction, setDirection] = useState('usd_to_lbp');
  const [bucket, setBucket] = useState('hour');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [analytics, setAnalytics] = useState(null);
  const [historyPoints, setHistoryPoints] = useState([]);

  useEffect(() => {
    const initializePage = async () => {
      let defaultBucket = 'hour';

      try {
        const response = await apiClient.get('/preferences');
        const prefs = response.data || {};
        setPreferences(prefs);
        defaultBucket = prefs.default_bucket || 'hour';
        setBucket(defaultBucket);
      } catch (err) {
        setPreferences({ default_range_hours: 72, default_bucket: 'hour' });
        setBucket(defaultBucket);
      }

      await loadAllData('usd_to_lbp', defaultBucket, '', '');
    };

    initializePage();
  }, []);

  const buildHistoryParams = (selectedDirection, selectedBucket, fromValue, toValue) => {
    const params = {
      direction: selectedDirection,
      bucket: selectedBucket,
    };

    if (fromValue && toValue) {
      params.from = fromValue;
      params.to = toValue;
    }

    return params;
  };

  const buildAnalyticsParams = (selectedDirection, fromValue, toValue) => {
    const params = {
      direction: selectedDirection,
    };

    if (fromValue && toValue) {
      params.from = fromValue;
      params.to = toValue;
    }

    return params;
  };

  const fetchHistory = async (selectedDirection, selectedBucket, fromValue, toValue) => {
    const response = await apiClient.get('/history/exchange-rate', {
      params: buildHistoryParams(selectedDirection, selectedBucket, fromValue, toValue),
    });
    return response.data;
  };

  const fetchAnalytics = async (selectedDirection, fromValue, toValue) => {
    const response = await apiClient.get('/analytics/exchange-rate', {
      params: buildAnalyticsParams(selectedDirection, fromValue, toValue),
    });
    return response.data;
  };

  const loadAllData = async (
    selectedDirection = direction,
    selectedBucket = bucket,
    fromValue = from,
    toValue = to
  ) => {
    try {
      setLoading(true);
      setError('');

      const [historyData, analyticsData] = await Promise.all([
        fetchHistory(selectedDirection, selectedBucket, fromValue, toValue),
        fetchAnalytics(selectedDirection, fromValue, toValue),
      ]);

      setHistoryPoints(Array.isArray(historyData.points) ? historyData.points : []);
      setAnalytics(analyticsData || null);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load history data');
      setHistoryPoints([]);
      setAnalytics(null);
    } finally {
      setLoading(false);
    }
  };

  const handleLoad = () => {
    setError('');

    if ((from && !to) || (!from && to)) {
      setError('Provide both "from" and "to" dates or neither');
      return;
    }

    loadAllData(direction, bucket, from, to);
  };

  const formatNumber = (value, digits = 4) => {
    return typeof value === 'number' ? value.toFixed(digits) : '-';
  };

  const formatPercent = (value) => {
    return typeof value === 'number' ? `${value.toFixed(2)}%` : '-';
  };

  return (
    <div style={styles.page}>
      <ProofPanel />

      <div style={styles.pageHeader}>
        <h1 style={styles.title}>History</h1>
        <p style={styles.subtitle}>
          View exchange rate history and analytics
        </p>
      </div>

      {error && <ErrorAlert message={error} onClose={() => setError('')} />}

      <div style={styles.card}>
        <h2 style={styles.sectionTitle}>Controls</h2>

        <div style={styles.controlsGrid}>
          <div style={styles.field}>
            <label style={styles.label}>Direction</label>
            <select
              value={direction}
              onChange={(e) => setDirection(e.target.value)}
              style={styles.input}
            >
              <option value="usd_to_lbp">USD to LBP</option>
              <option value="lbp_to_usd">LBP to USD</option>
            </select>
          </div>

          <div style={styles.field}>
            <label style={styles.label}>Bucket</label>
            <select
              value={bucket}
              onChange={(e) => setBucket(e.target.value)}
              style={styles.input}
            >
              <option value="hour">Hour</option>
              <option value="day">Day</option>
            </select>
          </div>

          <div style={styles.field}>
            <label style={styles.label}>From</label>
            <input
              type="datetime-local"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              style={styles.input}
            />
          </div>

          <div style={styles.field}>
            <label style={styles.label}>To</label>
            <input
              type="datetime-local"
              value={to}
              onChange={(e) => setTo(e.target.value)}
              style={styles.input}
            />
          </div>

          <div style={styles.field}>
            <label style={{ ...styles.label, visibility: 'hidden' }}>Load</label>
            <button
              onClick={handleLoad}
              disabled={loading}
              style={{
                ...styles.button,
                cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.8 : 1,
              }}
            >
              {loading ? 'Loading...' : 'Load History'}
            </button>
          </div>
        </div>

        {preferences && (
          <div style={styles.helperText}>
            Default bucket: <strong>{preferences.default_bucket || 'hour'}</strong> | Default range hours:{' '}
            <strong>{preferences.default_range_hours || 72}</strong>
          </div>
        )}
      </div>

      {loading && (
        <div style={styles.loadingText}>
          Loading history data...
        </div>
      )}

      {analytics && (
        <div style={styles.card}>
          <h2 style={styles.sectionTitle}>Analytics Summary</h2>

          <div style={styles.statsGrid}>
            <div style={styles.statCard}>
              <div style={styles.statLabel}>Direction</div>
              <div style={styles.statValueSmall}>{analytics.direction || '-'}</div>
            </div>

            <div style={styles.statCard}>
              <div style={styles.statLabel}>Total Transactions</div>
              <div style={styles.statValue}>{analytics.total_transactions ?? '-'}</div>
            </div>

            <div style={styles.statCard}>
              <div style={styles.statLabel}>Min Rate</div>
              <div style={styles.statValue}>{formatNumber(analytics.min_rate)}</div>
            </div>

            <div style={styles.statCard}>
              <div style={styles.statLabel}>Max Rate</div>
              <div style={styles.statValue}>{formatNumber(analytics.max_rate)}</div>
            </div>

            <div style={styles.statCard}>
              <div style={styles.statLabel}>Average Rate</div>
              <div style={styles.statValue}>{formatNumber(analytics.avg_rate)}</div>
            </div>

            <div style={styles.statCard}>
              <div style={styles.statLabel}>First Rate</div>
              <div style={styles.statValue}>{formatNumber(analytics.first_rate)}</div>
            </div>

            <div style={styles.statCard}>
              <div style={styles.statLabel}>Last Rate</div>
              <div style={styles.statValue}>{formatNumber(analytics.last_rate)}</div>
            </div>

            <div style={styles.statCard}>
              <div style={styles.statLabel}>Percentage Change</div>
              <div style={styles.statValue}>{formatPercent(analytics.percentage_change)}</div>
            </div>

            <div style={styles.statCard}>
              <div style={styles.statLabel}>From</div>
              <div style={styles.statValueSmall}>{analytics.from || '-'}</div>
            </div>

            <div style={styles.statCard}>
              <div style={styles.statLabel}>To</div>
              <div style={styles.statValueSmall}>{analytics.to || '-'}</div>
            </div>
          </div>
        </div>
      )}

      <div style={styles.card}>
        <h2 style={styles.sectionTitle}>History Points</h2>

        {historyPoints.length > 0 ? (
          <div style={{ width: '100%', height: 400 }}>
            <ResponsiveContainer>
              <LineChart data={historyPoints}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="t" />
                <YAxis />
                <Tooltip />
                <Line type="monotone" dataKey="rate" stroke="#8884d8" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        ) : (
          !loading && (
            <p style={styles.emptyText}>
              No history data found for the selected parameters.
            </p>
          )
        )}
      </div>
    </div>
  );
};

export default HistoryPage;