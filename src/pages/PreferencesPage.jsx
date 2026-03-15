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
    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
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
  helperText: {
    marginTop: '8px',
    color: '#6c757d',
    fontSize: '14px',
    lineHeight: 1.5,
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
    padding: '12px 20px',
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
    border: '1px solid #e9ecef',
    borderRadius: '10px',
    padding: '16px',
    marginTop: '18px',
  },
  infoTitle: {
    marginTop: 0,
    marginBottom: '8px',
    color: '#1f3b57',
  },
};

const PreferencesPage = () => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const [formData, setFormData] = useState({
    default_range_hours: '',
    default_bucket: 'hour',
  });

  const getErrorMessage = (err, fallback) =>
    err?.response?.data?.error ||
    err?.response?.data?.message ||
    err?.message ||
    fallback;

  useEffect(() => {
    fetchPreferences();
  }, []);

  const fetchPreferences = async () => {
    setLoading(true);
    setError('');

    try {
      const response = await apiClient.get('/preferences');
      const data = response.data || {};

      setFormData({
        default_range_hours:
          data.default_range_hours !== null && data.default_range_hours !== undefined
            ? String(data.default_range_hours)
            : '',
        default_bucket: data.default_bucket || 'hour',
      });
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to load preferences'));
    } finally {
      setLoading(false);
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
    if (formData.default_range_hours === '') {
      return 'Default analytics range is required';
    }

    const rangeNumber = Number(formData.default_range_hours);

    if (!Number.isInteger(rangeNumber)) {
      return 'Default analytics range must be a whole number';
    }

    if (rangeNumber < 1 || rangeNumber > 720) {
      return 'Default analytics range must be between 1 and 720 hours';
    }

    if (!['hour', 'day'].includes(formData.default_bucket)) {
      return 'Default graph interval is invalid';
    }

    return '';
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');

    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      return;
    }

    setSaving(true);

    try {
      const payload = {
        default_range_hours: Number(formData.default_range_hours),
        default_bucket: formData.default_bucket,
      };

      const response = await apiClient.put('/preferences', payload);
      const data = response.data || {};

      setFormData({
        default_range_hours:
          data.default_range_hours !== null && data.default_range_hours !== undefined
            ? String(data.default_range_hours)
            : String(payload.default_range_hours),
        default_bucket: data.default_bucket || payload.default_bucket,
      });

      setSuccessMessage(data.message || 'Preferences updated successfully');
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to save preferences'));
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div style={styles.page}>
        <ProofPanel />
        <h1>Preferences</h1>
        <p>Loading preferences...</p>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <ProofPanel />

      <h1 style={{ marginBottom: '8px', color: '#1f3b57' }}>Preferences</h1>
      <p style={styles.subtitle}>
        Configure your default analytics range and graph interval for a more consistent experience.
      </p>

      {error && <ErrorAlert message={error} onClose={() => setError('')} />}

      {successMessage && (
        <div style={styles.successMessage}>
          {successMessage}
        </div>
      )}

      <div style={styles.card}>
        <h2 style={styles.sectionHeader}>Default Settings</h2>

        <form onSubmit={handleSubmit}>
          <div style={styles.grid}>
            <div style={styles.field}>
              <label style={styles.label}>Default Analytics Range (hours)</label>
              <input
                type="number"
                name="default_range_hours"
                value={formData.default_range_hours}
                onChange={handleChange}
                min="1"
                max="720"
                step="1"
                placeholder="Enter hours"
                style={styles.input}
              />
              <p style={styles.helperText}>
                This will be used as the default range on analytics-related screens.
              </p>
            </div>

            <div style={styles.field}>
              <label style={styles.label}>Default Graph Interval</label>
              <select
                name="default_bucket"
                value={formData.default_bucket}
                onChange={handleChange}
                style={styles.input}
              >
                <option value="hour">Hour</option>
                <option value="day">Day</option>
              </select>
              <p style={styles.helperText}>
                This matches the backend-supported bucket values.
              </p>
            </div>
          </div>

          <div style={styles.buttonRow}>
            <button type="submit" style={styles.primaryButton} disabled={saving}>
              {saving ? 'Saving...' : 'Save Preferences'}
            </button>

            <button
              type="button"
              style={styles.secondaryButton}
              onClick={fetchPreferences}
              disabled={saving}
            >
              Reload Preferences
            </button>
          </div>
        </form>

        <div style={styles.infoBox}>
          <h3 style={styles.infoTitle}>Current backend-supported fields</h3>
          <p style={{ margin: 0, color: '#495057', lineHeight: 1.6 }}>
            This screen saves only <strong>default_range_hours</strong> and{' '}
            <strong>default_bucket</strong> because these are the real fields currently supported by
            the backend.
          </p>
        </div>
      </div>
    </div>
  );
};

export default PreferencesPage;