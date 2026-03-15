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
  topRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: '12px',
    flexWrap: 'wrap',
    marginBottom: '18px',
  },
  buttonRow: {
    display: 'flex',
    gap: '10px',
    flexWrap: 'wrap',
  },
  primaryButton: {
    backgroundColor: '#3498db',
    color: '#fff',
    border: 'none',
    borderRadius: '8px',
    padding: '10px 16px',
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
  filtersRow: {
    display: 'flex',
    gap: '12px',
    alignItems: 'center',
    flexWrap: 'wrap',
    marginBottom: '16px',
  },
  checkboxLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontWeight: '600',
    color: '#1f3b57',
  },
  notifList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '14px',
  },
  notifCard: {
    border: '1px solid #dee2e6',
    borderRadius: '12px',
    padding: '18px',
    backgroundColor: '#fff',
  },
  unreadCard: {
    border: '1px solid #b8daff',
    backgroundColor: '#f4f9ff',
  },
  notifHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: '12px',
    flexWrap: 'wrap',
    marginBottom: '10px',
  },
  notifTitle: {
    margin: 0,
    color: '#1f3b57',
  },
  metaText: {
    color: '#6c757d',
    fontSize: '14px',
    margin: '4px 0 0 0',
  },
  message: {
    margin: '10px 0',
    color: '#212529',
    lineHeight: 1.5,
  },
  badgeUnread: {
    display: 'inline-block',
    padding: '4px 10px',
    borderRadius: '999px',
    fontSize: '12px',
    fontWeight: '700',
    backgroundColor: '#e8f1ff',
    color: '#1a73e8',
  },
  badgeRead: {
    display: 'inline-block',
    padding: '4px 10px',
    borderRadius: '999px',
    fontSize: '12px',
    fontWeight: '700',
    backgroundColor: '#f1f3f5',
    color: '#6c757d',
  },
  smallActions: {
    display: 'flex',
    gap: '10px',
    flexWrap: 'wrap',
    marginTop: '12px',
  },
  readButton: {
    backgroundColor: '#28a745',
    color: '#fff',
    border: 'none',
    borderRadius: '8px',
    padding: '8px 14px',
    fontWeight: '600',
    cursor: 'pointer',
  },
  deleteButton: {
    backgroundColor: '#dc3545',
    color: '#fff',
    border: 'none',
    borderRadius: '8px',
    padding: '8px 14px',
    fontWeight: '600',
    cursor: 'pointer',
  },
  emptyText: {
    color: '#6c757d',
    margin: 0,
  },
};

const NotificationsPage = () => {
  const [notifications, setNotifications] = useState([]);
  const [pageLoading, setPageLoading] = useState(true);
  const [listLoading, setListLoading] = useState(false);
  const [actionLoadingId, setActionLoadingId] = useState(null);
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const getErrorMessage = (err, fallback) =>
    err?.response?.data?.error ||
    err?.response?.data?.message ||
    err?.message ||
    fallback;

  useEffect(() => {
    initializePage();
  }, []);

  useEffect(() => {
    fetchNotifications();
  }, [unreadOnly]);

  const initializePage = async () => {
    setPageLoading(true);
    setError('');
    await fetchNotifications();
    setPageLoading(false);
  };

  const fetchNotifications = async () => {
    setListLoading(true);
    setError('');

    try {
      const response = await apiClient.get('/notifications', {
        params: { unread_only: unreadOnly },
      });
      setNotifications(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to load notifications'));
    } finally {
      setListLoading(false);
    }
  };

  const handleMarkRead = async (notificationId) => {
    setActionLoadingId(notificationId);
    setError('');
    setSuccessMessage('');

    try {
      await apiClient.patch(`/notifications/${notificationId}/read`);
      setSuccessMessage('Notification marked as read');
      await fetchNotifications();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to mark notification as read'));
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleDelete = async (notificationId) => {
    setActionLoadingId(notificationId);
    setError('');
    setSuccessMessage('');

    try {
      await apiClient.delete(`/notifications/${notificationId}`);
      setSuccessMessage('Notification deleted');
      await fetchNotifications();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to delete notification'));
    } finally {
      setActionLoadingId(null);
    }
  };

  if (pageLoading) {
    return (
      <div style={styles.page}>
        <ProofPanel />
        <h1>Notifications</h1>
        <p>Loading notifications...</p>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <ProofPanel />

      <h1 style={{ marginBottom: '8px', color: '#1f3b57' }}>Notifications</h1>
      <p style={styles.subtitle}>
        View system notifications, mark them as read, or remove them.
      </p>

      {error && <ErrorAlert message={error} onClose={() => setError('')} />}

      {successMessage && (
        <div style={styles.successMessage}>
          {successMessage}
        </div>
      )}

      <div style={styles.card}>
        <div style={styles.topRow}>
          <h2 style={{ ...styles.sectionHeader, marginBottom: 0 }}>My Notifications</h2>

          <div style={styles.buttonRow}>
            <button
              type="button"
              style={styles.primaryButton}
              onClick={fetchNotifications}
              disabled={listLoading}
            >
              {listLoading ? 'Refreshing...' : 'Refresh Notifications'}
            </button>
          </div>
        </div>

        <div style={styles.filtersRow}>
          <label style={styles.checkboxLabel}>
            <input
              type="checkbox"
              checked={unreadOnly}
              onChange={(e) => setUnreadOnly(e.target.checked)}
            />
            Show unread only
          </label>
        </div>

        {notifications.length === 0 ? (
          <p style={styles.emptyText}>No notifications found.</p>
        ) : (
          <div style={styles.notifList}>
            {notifications.map((notification) => (
              <div
                key={notification.id}
                style={{
                  ...styles.notifCard,
                  ...(notification.is_read ? {} : styles.unreadCard),
                }}
              >
                <div style={styles.notifHeader}>
                  <div>
                    <h3 style={styles.notifTitle}>
                      {notification.title || 'Notification'}
                    </h3>
                    <p style={styles.metaText}>
                      Event: {notification.event_type || '—'}
                    </p>
                    <p style={styles.metaText}>
                      Created at: {notification.created_at || '—'}
                    </p>
                    <p style={styles.metaText}>
                      Ref: {notification.ref_type || '—'} {notification.ref_id ?? ''}
                    </p>
                  </div>

                  <div>
                    {notification.is_read ? (
                      <span style={styles.badgeRead}>Read</span>
                    ) : (
                      <span style={styles.badgeUnread}>Unread</span>
                    )}
                  </div>
                </div>

                <p style={styles.message}>{notification.message || 'No message'}</p>

                <div style={styles.smallActions}>
                  {!notification.is_read && (
                    <button
                      type="button"
                      style={styles.readButton}
                      onClick={() => handleMarkRead(notification.id)}
                      disabled={actionLoadingId === notification.id}
                    >
                      {actionLoadingId === notification.id ? 'Please wait...' : 'Mark as Read'}
                    </button>
                  )}

                  <button
                    type="button"
                    style={styles.deleteButton}
                    onClick={() => handleDelete(notification.id)}
                    disabled={actionLoadingId === notification.id}
                  >
                    {actionLoadingId === notification.id ? 'Please wait...' : 'Delete'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default NotificationsPage;