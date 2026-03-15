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
  helperText: {
    fontSize: '14px',
    color: '#6c757d',
    marginTop: '10px',
  },
  pill: {
    display: 'inline-block',
    padding: '4px 10px',
    borderRadius: '999px',
    fontSize: '12px',
    fontWeight: '700',
    backgroundColor: '#e9f2ff',
    color: '#1a73e8',
  },
  thresholdPill: {
    display: 'inline-block',
    padding: '4px 10px',
    borderRadius: '999px',
    fontSize: '12px',
    fontWeight: '700',
    backgroundColor: '#fff4e5',
    color: '#b26a00',
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
    verticalAlign: 'top',
  },
  emptyText: {
    color: '#6c757d',
    margin: 0,
  },
};

const WatchlistPage = () => {
  const [items, setItems] = useState([]);
  const [pageLoading, setPageLoading] = useState(true);
  const [listLoading, setListLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const [formData, setFormData] = useState({
    item_type: 'direction',
    direction: 'usd_to_lbp',
    condition: 'above',
    threshold: '',
  });

  useEffect(() => {
    initializePage();
  }, []);

  const getErrorMessage = (err, fallback) =>
    err?.response?.data?.error ||
    err?.response?.data?.message ||
    err?.message ||
    fallback;

  const initializePage = async () => {
    setPageLoading(true);
    setError('');
    await fetchWatchlist();
    setPageLoading(false);
  };

  const fetchWatchlist = async () => {
    setListLoading(true);
    try {
      const response = await apiClient.get('/watchlist');
      setItems(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to load watchlist'));
    } finally {
      setListLoading(false);
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;

    setFormData((prev) => {
      const updated = {
        ...prev,
        [name]: value,
      };

      if (name === 'item_type' && value === 'direction') {
        updated.condition = 'above';
        updated.threshold = '';
      }

      return updated;
    });
  };

  const validateForm = () => {
    if (!formData.item_type || !formData.direction) {
      return 'Item type and direction are required';
    }

    if (!['direction', 'threshold'].includes(formData.item_type)) {
      return 'Item type is invalid';
    }

    if (!['usd_to_lbp', 'lbp_to_usd'].includes(formData.direction)) {
      return 'Direction is invalid';
    }

    if (formData.item_type === 'threshold') {
      if (!['above', 'below'].includes(formData.condition)) {
        return 'Condition is invalid';
      }

      if (formData.threshold === '') {
        return 'Threshold is required for threshold items';
      }

      const thresholdNumber = Number(formData.threshold);
      if (Number.isNaN(thresholdNumber)) {
        return 'Threshold must be a number';
      }

      if (thresholdNumber <= 0) {
        return 'Threshold must be greater than 0';
      }
    }

    return '';
  };

  const handleAddItem = async (e) => {
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
      const payload = {
        item_type: formData.item_type,
        direction: formData.direction,
      };

      if (formData.item_type === 'threshold') {
        payload.condition = formData.condition;
        payload.threshold = Number(formData.threshold);
      }

      await apiClient.post('/watchlist', payload);

      setSuccessMessage('Watchlist item added successfully');
      setFormData({
        item_type: 'direction',
        direction: 'usd_to_lbp',
        condition: 'above',
        threshold: '',
      });

      await fetchWatchlist();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to add watchlist item'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteItem = async (itemId) => {
    setError('');
    setSuccessMessage('');

    try {
      await apiClient.delete(`/watchlist/${itemId}`);
      setSuccessMessage('Watchlist item removed successfully');
      await fetchWatchlist();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to remove watchlist item'));
    }
  };

  const renderItemTypeBadge = (itemType) => {
    if (itemType === 'threshold') {
      return <span style={styles.thresholdPill}>Threshold</span>;
    }
    return <span style={styles.pill}>Direction</span>;
  };

  if (pageLoading) {
    return (
      <div style={styles.page}>
        <ProofPanel />
        <h1>Watchlist</h1>
        <p>Loading watchlist...</p>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <ProofPanel />

      <h1 style={{ marginBottom: '8px', color: '#1f3b57' }}>Watchlist</h1>
      <p style={styles.subtitle}>
        Save favorite exchange directions or threshold conditions and manage them easily.
      </p>

      {error && <ErrorAlert message={error} onClose={() => setError('')} />}

      {successMessage && (
        <div style={styles.successMessage}>
          {successMessage}
        </div>
      )}

      <div style={styles.card}>
        <h2 style={styles.sectionHeader}>Add Watchlist Item</h2>

        <form onSubmit={handleAddItem}>
          <div style={styles.grid}>
            <div style={styles.field}>
              <label style={styles.label}>Item Type</label>
              <select
                name="item_type"
                value={formData.item_type}
                onChange={handleChange}
                style={styles.input}
              >
                <option value="direction">Direction</option>
                <option value="threshold">Threshold</option>
              </select>
            </div>

            <div style={styles.field}>
              <label style={styles.label}>Direction</label>
              <select
                name="direction"
                value={formData.direction}
                onChange={handleChange}
                style={styles.input}
              >
                <option value="usd_to_lbp">USD to LBP</option>
                <option value="lbp_to_usd">LBP to USD</option>
              </select>
            </div>

            {formData.item_type === 'threshold' && (
              <>
                <div style={styles.field}>
                  <label style={styles.label}>Condition</label>
                  <select
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
                  <label style={styles.label}>Threshold</label>
                  <input
                    type="number"
                    step="any"
                    name="threshold"
                    value={formData.threshold}
                    onChange={handleChange}
                    placeholder="Enter threshold"
                    style={styles.input}
                  />
                </div>
              </>
            )}
          </div>

          <div style={styles.buttonRow}>
            <button type="submit" style={styles.primaryButton} disabled={submitting}>
              {submitting ? 'Adding...' : 'Add to Watchlist'}
            </button>
          </div>

          <p style={styles.helperText}>
            Direction items save only the selected direction. Threshold items save direction + condition + threshold.
          </p>
        </form>
      </div>

      <div style={styles.card}>
        <div style={styles.topRow}>
          <h2 style={{ ...styles.sectionHeader, marginBottom: 0 }}>My Watchlist</h2>
          <button
            type="button"
            style={styles.secondaryButton}
            onClick={fetchWatchlist}
            disabled={listLoading}
          >
            {listLoading ? 'Refreshing...' : 'Refresh Watchlist'}
          </button>
        </div>

        {items.length === 0 ? (
          <p style={styles.emptyText}>No watchlist items yet.</p>
        ) : (
          <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Type</th>
                  <th style={styles.th}>Direction</th>
                  <th style={styles.th}>Condition</th>
                  <th style={styles.th}>Threshold</th>
                  <th style={styles.th}>Created At</th>
                  <th style={styles.th}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id}>
                    <td style={styles.td}>{renderItemTypeBadge(item.item_type)}</td>
                    <td style={styles.td}>
                      {item.direction === 'usd_to_lbp' ? 'USD to LBP' : 'LBP to USD'}
                    </td>
                    <td style={styles.td}>{item.condition || '—'}</td>
                    <td style={styles.td}>
                      {item.threshold !== null && item.threshold !== undefined ? item.threshold : '—'}
                    </td>
                    <td style={styles.td}>{item.created_at || '—'}</td>
                    <td style={styles.td}>
                      <button
                        type="button"
                        style={styles.dangerButton}
                        onClick={() => handleDeleteItem(item.id)}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default WatchlistPage;