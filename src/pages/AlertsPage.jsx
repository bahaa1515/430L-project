import React, { useEffect, useState } from 'react';
import apiClient from '../api/apiClient';
import ErrorAlert from '../components/ErrorAlert';
import ProofPanel from '../components/ProofPanel';

const styles = {
  page: {
    padding: '24px',
  },
  subtitle: {
    color: '#6c757d',
    marginBottom: '24px',
  },
  card: {
    backgroundColor: '#ffffff',
    border: '1px solid #dee2e6',
    borderRadius: '12px',
    padding: '24px',
    marginBottom: '24px',
    boxShadow: '0 2px 8px rgba(0,0,0,0.04)',
  },
  sectionHeader: {
    marginTop: 0,
    marginBottom: '18px',
    color: '#1f3b57',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
    gap: '16px',
  },
  field: {
    display: 'flex',
    flexDirection: 'column',
  },
  label: {
    marginBottom: '8px',
    fontWeight: '600',
    color: '#1f3b57',
  },
  input: {
    padding: '12px',
    borderRadius: '8px',
    border: '1px solid #ced4da',
    fontSize: '15px',
  },
  topRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: '12px',
    marginBottom: '14px',
    flexWrap: 'wrap',
  },
  buttonRow: {
    display: 'flex',
    gap: '12px',
    flexWrap: 'wrap',
    marginTop: '18px',
  },
  primaryButton: {
    backgroundColor: '#28a745',
    color: '#fff',
    border: 'none',
    borderRadius: '8px',
    padding: '12px 20px',
    fontWeight: '600',
    cursor: 'pointer',
  },
  secondaryButton: {
    backgroundColor: '#3498db',
    color: '#fff',
    border: 'none',
    borderRadius: '8px',
    padding: '10px 18px',
    fontWeight: '600',
    cursor: 'pointer',
  },
  dangerButton: {
    backgroundColor: '#dc3545',
    color: '#fff',
    border: 'none',
    borderRadius: '8px',
    padding: '9px 16px',
    fontWeight: '600',
    cursor: 'pointer',
  },
  successMessage: {
    backgroundColor: '#d4edda',
    color: '#155724',
    border: '1px solid #c3e6cb',
    borderRadius: '8px',
    padding: '12px 14px',
    marginBottom: '18px',
  },
  infoBox: {
    backgroundColor: '#f8f9fa',
    border: '1px solid #dee2e6',
    borderRadius: '8px',
    padding: '12px 14px',
    marginBottom: '16px',
    color: '#1f3b57',
    fontWeight: '500',
  },
  tableWrapper: {
    overflowX: 'auto',
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
    padding: '14px',
    fontWeight: '700',
  },
  td: {
    padding: '14px',
    borderTop: '1px solid #e9ecef',
  },
};

const AlertsPage = () => {
  const [alerts, setAlerts] = useState([]);
  const [triggeredAlerts, setTriggeredAlerts] = useState([]);
  const [currentRates, setCurrentRates] = useState({
    usd_to_lbp: null,
    lbp_to_usd: null,
  });

  const [pageLoading, setPageLoading] = useState(true);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [triggeredLoading, setTriggeredLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const [formData, setFormData] = useState({
    direction: 'usd_to_lbp',
    condition: 'above',
    threshold: '',
  });

  useEffect(() => {
    initializePage();
  }, []);

  const getErrorMessage = (err, fallback) => {
    return (
      err?.response?.data?.error ||
      err?.response?.data?.message ||
      err?.message ||
      fallback
    );
  };

  const initializePage = async () => {
    setPageLoading(true);
    setError('');
    await Promise.all([fetchAlerts(), fetchTriggeredAlerts()]);
    setPageLoading(false);
  };

  const fetchAlerts = async () => {
    setAlertsLoading(true);
    try {
      const response = await apiClient.get('/alerts');
      setAlerts(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to load alerts'));
    } finally {
      setAlertsLoading(false);
    }
  };

  const fetchTriggeredAlerts = async () => {
    setTriggeredLoading(true);
    try {
      const response = await apiClient.get('/alerts/triggered');
      setTriggeredAlerts(Array.isArray(response.data?.triggered) ? response.data.triggered : []);
      setCurrentRates({
        usd_to_lbp: response.data?.current_rates?.usd_to_lbp ?? null,
        lbp_to_usd: response.data?.current_rates?.lbp_to_usd ?? null,
      });
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to load triggered alerts'));
    } finally {
      setTriggeredLoading(false);
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const validateForm = () => {
    if (!formData.direction || !formData.condition || formData.threshold === '') {
      return 'All fields are required';
    }

    if (!['usd_to_lbp', 'lbp_to_usd'].includes(formData.direction)) {
      return 'Direction is invalid';
    }

    if (!['above', 'below'].includes(formData.condition)) {
      return 'Condition is invalid';
    }

    const thresholdNumber = Number(formData.threshold);
    if (Number.isNaN(thresholdNumber)) {
      return 'Threshold must be a number';
    }

    if (thresholdNumber <= 0) {
      return 'Threshold must be greater than 0';
    }

    return '';
  };

  const handleCreateAlert = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');

    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      return;
    }

    setSubmitting(true);

    try {
      await apiClient.post('/alerts', {
        direction: formData.direction,
        condition: formData.condition,
        threshold: Number(formData.threshold),
      });

      setSuccessMessage('Alert created successfully');
      setFormData({
        direction: 'usd_to_lbp',
        condition: 'above',
        threshold: '',
      });

      await fetchAlerts();
      await fetchTriggeredAlerts();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to create alert'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteAlert = async (alertId) => {
    setError('');
    setSuccessMessage('');

    try {
      await apiClient.delete(`/alerts/${alertId}`);
      setSuccessMessage(`Alert #${alertId} deleted successfully`);
      await fetchAlerts();
      await fetchTriggeredAlerts();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to delete alert'));
    }
  };

  const formatDateTime = (value) => {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
  };

  if (pageLoading) {
    return (
      <div style={styles.page}>
        <ProofPanel />
        <h1>Alerts</h1>
        <p>Loading alerts...</p>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <ProofPanel />

      <h1>Alerts</h1>
      <p style={styles.subtitle}>
        Create exchange rate alerts, manage them, and monitor which alerts are currently triggered.
      </p>

      {error && <ErrorAlert message={error} />}
      {successMessage && <div style={styles.successMessage}>{successMessage}</div>}

      <section style={styles.card}>
        <h2 style={styles.sectionHeader}>Create Alert</h2>

        <form onSubmit={handleCreateAlert}>
          <div style={styles.grid}>
            <div style={styles.field}>
              <label htmlFor="direction" style={styles.label}>Direction</label>
              <select
                id="direction"
                name="direction"
                value={formData.direction}
                onChange={handleChange}
                style={styles.input}
              >
                <option value="usd_to_lbp">USD to LBP</option>
                <option value="lbp_to_usd">LBP to USD</option>
              </select>
            </div>

            <div style={styles.field}>
              <label htmlFor="condition" style={styles.label}>Condition</label>
              <select
                id="condition"
                name="condition"
                value={formData.condition}
                onChange={handleChange}
                style={styles.input}
              >
                <option value="above">Above</option>
                <option value="below">Below</option>
              </select>
            </div>

            <div style={styles.field}>
              <label htmlFor="threshold" style={styles.label}>Threshold</label>
              <input
                id="threshold"
                name="threshold"
                type="number"
                min="0"
                step="any"
                value={formData.threshold}
                onChange={handleChange}
                placeholder="Enter threshold"
                style={styles.input}
              />
            </div>
          </div>

          <div style={styles.buttonRow}>
            <button type="submit" disabled={submitting} style={styles.primaryButton}>
              {submitting ? 'Creating...' : 'Add Alert'}
            </button>
          </div>
        </form>
      </section>

      <section style={styles.card}>
        <div style={styles.topRow}>
          <h2 style={styles.sectionHeader}>My Alerts</h2>
          <button type="button" onClick={fetchAlerts} disabled={alertsLoading} style={styles.secondaryButton}>
            {alertsLoading ? 'Refreshing...' : 'Refresh Alerts'}
          </button>
        </div>

        {alerts.length === 0 ? (
          <p>No alerts found.</p>
        ) : (
          <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>ID</th>
                  <th style={styles.th}>Direction</th>
                  <th style={styles.th}>Condition</th>
                  <th style={styles.th}>Threshold</th>
                  <th style={styles.th}>Active</th>
                  <th style={styles.th}>Triggered At</th>
                  <th style={styles.th}>Created At</th>
                  <th style={styles.th}>Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td style={styles.td}>{alert.id}</td>
                    <td style={styles.td}>{alert.direction}</td>
                    <td style={styles.td}>{alert.condition}</td>
                    <td style={styles.td}>{alert.threshold}</td>
                    <td style={styles.td}>{alert.is_active ? 'Yes' : 'No'}</td>
                    <td style={styles.td}>{formatDateTime(alert.triggered_at)}</td>
                    <td style={styles.td}>{formatDateTime(alert.created_at)}</td>
                    <td style={styles.td}>
                      <button
                        type="button"
                        onClick={() => handleDeleteAlert(alert.id)}
                        style={styles.dangerButton}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section style={styles.card}>
        <div style={styles.topRow}>
          <h2 style={styles.sectionHeader}>Triggered Alerts</h2>
          <button
            type="button"
            onClick={fetchTriggeredAlerts}
            disabled={triggeredLoading}
            style={styles.secondaryButton}
          >
            {triggeredLoading ? 'Refreshing...' : 'Check Triggered'}
          </button>
        </div>

        <div style={styles.infoBox}>
          Current Rates: USD→LBP: {currentRates.usd_to_lbp ?? '-'} | LBP→USD: {currentRates.lbp_to_usd ?? '-'}
        </div>

        {triggeredAlerts.length === 0 ? (
          <p>No triggered alerts right now.</p>
        ) : (
          <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>ID</th>
                  <th style={styles.th}>Direction</th>
                  <th style={styles.th}>Condition</th>
                  <th style={styles.th}>Threshold</th>
                  <th style={styles.th}>Current Rate</th>
                  <th style={styles.th}>Triggered At</th>
                </tr>
              </thead>
              <tbody>
                {triggeredAlerts.map((alert) => (
                  <tr key={alert.id}>
                    <td style={styles.td}>{alert.id}</td>
                    <td style={styles.td}>{alert.direction}</td>
                    <td style={styles.td}>{alert.condition}</td>
                    <td style={styles.td}>{alert.threshold}</td>
                    <td style={styles.td}>{alert.current_rate}</td>
                    <td style={styles.td}>{formatDateTime(alert.triggered_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};

export default AlertsPage;