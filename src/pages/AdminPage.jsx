import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import apiClient from '../api/apiClient';
import ErrorAlert from '../components/ErrorAlert';
import ProofPanel from '../components/ProofPanel';
import { ROUTES, getRoute } from '../utils/routeHelper';

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
  statGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
    gap: '16px',
  },
  statCard: {
    backgroundColor: '#f8f9fa',
    border: '1px solid #e9ecef',
    borderRadius: '10px',
    padding: '16px',
  },
  statLabel: {
    margin: 0,
    fontSize: '14px',
    color: '#6c757d',
  },
  statValue: {
    margin: '10px 0 0 0',
    fontSize: '26px',
    fontWeight: '700',
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
    whiteSpace: 'nowrap',
  },
  td: {
    padding: '14px',
    borderTop: '1px solid #e9ecef',
    verticalAlign: 'top',
  },
  actionGroup: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
  },
  select: {
    padding: '10px',
    borderRadius: '8px',
    border: '1px solid #ced4da',
    fontSize: '14px',
    backgroundColor: '#fff',
  },
  smallButton: {
    backgroundColor: '#28a745',
    color: '#fff',
    border: 'none',
    borderRadius: '8px',
    padding: '8px 12px',
    fontWeight: '600',
    cursor: 'pointer',
  },
  neutralButton: {
    backgroundColor: '#6c757d',
    color: '#fff',
    border: 'none',
    borderRadius: '8px',
    padding: '8px 12px',
    fontWeight: '600',
    cursor: 'pointer',
  },
  filtersGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
    gap: '14px',
    marginBottom: '16px',
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
    padding: '10px 12px',
    borderRadius: '8px',
    border: '1px solid #ced4da',
    fontSize: '14px',
  },
  emptyText: {
    color: '#6c757d',
    margin: 0,
  },
  pre: {
    margin: 0,
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
    fontSize: '13px',
    color: '#495057',
  },
  badgeActive: {
    display: 'inline-block',
    padding: '4px 10px',
    borderRadius: '999px',
    fontSize: '12px',
    fontWeight: '700',
    backgroundColor: '#d4edda',
    color: '#155724',
  },
  badgeSuspended: {
    display: 'inline-block',
    padding: '4px 10px',
    borderRadius: '999px',
    fontSize: '12px',
    fontWeight: '700',
    backgroundColor: '#fff3cd',
    color: '#856404',
  },
  badgeBanned: {
    display: 'inline-block',
    padding: '4px 10px',
    borderRadius: '999px',
    fontSize: '12px',
    fontWeight: '700',
    backgroundColor: '#f8d7da',
    color: '#721c24',
  },
  badgeAdmin: {
    display: 'inline-block',
    padding: '4px 10px',
    borderRadius: '999px',
    fontSize: '12px',
    fontWeight: '700',
    backgroundColor: '#e8f1ff',
    color: '#1a73e8',
  },
  badgeUser: {
    display: 'inline-block',
    padding: '4px 10px',
    borderRadius: '999px',
    fontSize: '12px',
    fontWeight: '700',
    backgroundColor: '#f1f3f5',
    color: '#495057',
  },
  forbiddenCard: {
    backgroundColor: '#fff3f3',
    border: '1px solid #f5c2c7',
    color: '#842029',
    borderRadius: '12px',
    padding: '24px',
  },
};

const AdminPage = () => {
  const navigate = useNavigate();

  const [pageLoading, setPageLoading] = useState(true);
  const [forbidden, setForbidden] = useState(false);

  const [users, setUsers] = useState([]);
  const [stats, setStats] = useState(null);
  const [logsData, setLogsData] = useState({ total: 0, offset: 0, limit: 20, logs: [] });
  const [dataQuality, setDataQuality] = useState(null);

  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const [actionLoadingKey, setActionLoadingKey] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  const [userEdits, setUserEdits] = useState({});

  const [logFilters, setLogFilters] = useState({
    from: '',
    to: '',
    actor_user_id: '',
    target_user_id: '',
    event_type: '',
    success: '',
    limit: '20',
    offset: '0',
  });

  const [qualityFilters, setQualityFilters] = useState({
    from: '',
    to: '',
    direction: '',
  });

  // Backup/Restore states
  const [backupLoading, setBackupLoading] = useState(false);
  const [restoreLoading, setRestoreLoading] = useState(false);
  const [statusLoading, setStatusLoading] = useState(false);
  const [backupStatus, setBackupStatus] = useState(null);

  const getErrorMessage = (err, fallback) =>
    err?.response?.data?.error ||
    err?.response?.data?.message ||
    err?.message ||
    fallback;

  const initializeUserEdits = (usersList) => {
    const next = {};
    usersList.forEach((user) => {
      next[user.id] = {
        status: user.status || 'ACTIVE',
        role: user.role || 'USER',
      };
    });
    setUserEdits(next);
  };

  const fetchUsers = async () => {
    const response = await apiClient.get('/admin/users');
    const data = Array.isArray(response.data) ? response.data : [];
    setUsers(data);
    initializeUserEdits(data);
    return data;
  };

  const fetchStats = async () => {
    const response = await apiClient.get('/admin/stats/transactions');
    setStats(response.data || null);
    return response.data;
  };

  const fetchLogs = async (customFilters = logFilters) => {
    const params = {
      limit: Number(customFilters.limit || 20),
      offset: Number(customFilters.offset || 0),
    };

    if (customFilters.from) params.from = customFilters.from;
    if (customFilters.to) params.to = customFilters.to;
    if (customFilters.actor_user_id) params.actor_user_id = Number(customFilters.actor_user_id);
    if (customFilters.target_user_id) params.target_user_id = Number(customFilters.target_user_id);
    if (customFilters.event_type) params.event_type = customFilters.event_type;
    if (customFilters.success !== '') params.success = customFilters.success;

    const response = await apiClient.get('/admin/logs', { params });
    setLogsData(response.data || { total: 0, offset: 0, limit: 20, logs: [] });
    return response.data;
  };

  const fetchDataQuality = async (customFilters = qualityFilters) => {
    const params = {};

    if (customFilters.from) params.from = customFilters.from;
    if (customFilters.to) params.to = customFilters.to;
    if (customFilters.direction) params.direction = customFilters.direction;

    const response = await apiClient.get('/admin/data-quality', { params });
    setDataQuality(response.data || null);
    return response.data;
  };

  const initializePage = async () => {
    setPageLoading(true);
    setError('');
    setForbidden(false);

    try {
      await Promise.all([
        fetchUsers(),
        fetchStats(),
        fetchLogs(),
        fetchDataQuality(),
      ]);
    } catch (err) {
      const status = err?.response?.status;
      if (status === 403) {
        setForbidden(true);
        setTimeout(() => {
          navigate(getRoute(ROUTES.DASHBOARD));
        }, 1800);
      } else {
        setError(getErrorMessage(err, 'Failed to load admin page'));
      }
    } finally {
      setPageLoading(false);
    }
  };

  useEffect(() => {
    initializePage();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleRefreshAll = async () => {
    setRefreshing(true);
    setError('');
    setSuccessMessage('');

    try {
      await Promise.all([
        fetchUsers(),
        fetchStats(),
        fetchLogs(),
        fetchDataQuality(),
      ]);
      setSuccessMessage('Admin data refreshed');
    } catch (err) {
      const status = err?.response?.status;
      if (status === 403) {
        setForbidden(true);
        setTimeout(() => {
          navigate(getRoute(ROUTES.DASHBOARD));
        }, 1800);
      } else {
        setError(getErrorMessage(err, 'Failed to refresh admin data'));
      }
    } finally {
      setRefreshing(false);
    }
  };

  const handleUserEditChange = (userId, field, value) => {
    setUserEdits((prev) => ({
      ...prev,
      [userId]: {
        ...(prev[userId] || {}),
        [field]: value,
      },
    }));
  };

  const handleUpdateStatus = async (userId) => {
    const nextStatus = userEdits[userId]?.status;
    if (!nextStatus) return;

    setActionLoadingKey(`status-${userId}`);
    setError('');
    setSuccessMessage('');

    try {
      const response = await apiClient.put(`/admin/users/${userId}/status`, {
        status: nextStatus,
      });

      setSuccessMessage(response?.data?.message || 'User status updated');
      await fetchUsers();
      await fetchLogs();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to update user status'));
    } finally {
      setActionLoadingKey('');
    }
  };

  const handleUpdateRole = async (userId) => {
    const nextRole = userEdits[userId]?.role;
    if (!nextRole) return;

    setActionLoadingKey(`role-${userId}`);
    setError('');
    setSuccessMessage('');

    try {
      const response = await apiClient.put(`/admin/users/${userId}/role`, {
        role: nextRole,
      });

      setSuccessMessage(response?.data?.message || 'User role updated');
      await fetchUsers();
      await fetchLogs();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to update user role'));
    } finally {
      setActionLoadingKey('');
    }
  };

  const handleLogFilterChange = (e) => {
    const { name, value } = e.target;
    setLogFilters((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleQualityFilterChange = (e) => {
    const { name, value } = e.target;
    setQualityFilters((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const applyLogFilters = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');

    try {
      await fetchLogs(logFilters);
      setSuccessMessage('Audit logs updated');
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to load audit logs'));
    }
  };

  const resetLogFilters = async () => {
    const reset = {
      from: '',
      to: '',
      actor_user_id: '',
      target_user_id: '',
      event_type: '',
      success: '',
      limit: '20',
      offset: '0',
    };
    setLogFilters(reset);
    setError('');
    setSuccessMessage('');

    try {
      await fetchLogs(reset);
      setSuccessMessage('Audit log filters cleared');
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to reset audit log filters'));
    }
  };

  const applyQualityFilters = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');

    try {
      await fetchDataQuality(qualityFilters);
      setSuccessMessage('Data quality report updated');
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to load data quality report'));
    }
  };

  const handleCreateBackup = async () => {
    setBackupLoading(true);
    setError('');
    setSuccessMessage('');

    try {
      await apiClient.post('/admin/backup');
      setSuccessMessage('Backup created successfully');
      await fetchBackupStatus();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to create backup'));
    } finally {
      setBackupLoading(false);
    }
  };

  const handleRestoreBackup = async () => {
    if (!window.confirm('Are you sure you want to restore from backup? This will overwrite current data.')) return;

    setRestoreLoading(true);
    setError('');
    setSuccessMessage('');

    try {
      await apiClient.post('/admin/restore');
      setSuccessMessage('Backup restored successfully');
      await fetchBackupStatus();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to restore backup'));
    } finally {
      setRestoreLoading(false);
    }
  };

  const fetchBackupStatus = async () => {
    setStatusLoading(true);
    try {
      const response = await apiClient.get('/admin/backup/status');
      setBackupStatus(response.data);
    } catch (err) {
      console.error('Failed to fetch backup status:', err);
    } finally {
      setStatusLoading(false);
    }
  };

  const resetQualityFilters = async () => {
    const reset = {
      from: '',
      to: '',
      direction: '',
    };
    setQualityFilters(reset);
    setError('');
    setSuccessMessage('');

    try {
      await fetchDataQuality(reset);
      setSuccessMessage('Data quality filters cleared');
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to reset data quality filters'));
    }
  };

  const renderStatusBadge = (status) => {
    if (status === 'ACTIVE') return <span style={styles.badgeActive}>ACTIVE</span>;
    if (status === 'SUSPENDED') return <span style={styles.badgeSuspended}>SUSPENDED</span>;
    return <span style={styles.badgeBanned}>BANNED</span>;
  };

  const renderRoleBadge = (role) => {
    if (role === 'ADMIN') return <span style={styles.badgeAdmin}>ADMIN</span>;
    return <span style={styles.badgeUser}>USER</span>;
  };

  const anomalyRows = useMemo(() => {
    return Array.isArray(dataQuality?.anomalies) ? dataQuality.anomalies : [];
  }, [dataQuality]);

  if (pageLoading) {
    return (
      <div style={styles.page}>
        <ProofPanel />
        <h1>Admin</h1>
        <p>Loading admin page...</p>
      </div>
    );
  }

  if (forbidden) {
    return (
      <div style={styles.page}>
        <ProofPanel />
        <div style={styles.forbiddenCard}>
          <h1 style={{ marginTop: 0 }}>Forbidden</h1>
          <p style={{ marginBottom: 0 }}>
            This page is for ADMIN users only. You will be redirected to the dashboard.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <ProofPanel />

      <h1 style={{ marginBottom: '8px', color: '#1f3b57' }}>Admin Dashboard</h1>
      <p style={styles.subtitle}>
        Manage users, review system-wide activity, inspect audit logs, and monitor data quality.
      </p>

      {error && <ErrorAlert message={error} onClose={() => setError('')} />}

      {successMessage && (
        <div style={styles.successMessage}>
          {successMessage}
        </div>
      )}

      <div style={styles.card}>
        <div style={styles.topRow}>
          <h2 style={{ ...styles.sectionHeader, marginBottom: 0 }}>Overview</h2>
          <div style={styles.buttonRow}>
            <button
              type="button"
              style={styles.primaryButton}
              onClick={handleRefreshAll}
              disabled={refreshing}
            >
              {refreshing ? 'Refreshing...' : 'Refresh Admin Data'}
            </button>
          </div>
        </div>

        <div style={styles.statGrid}>
          <div style={styles.statCard}>
            <p style={styles.statLabel}>Users</p>
            <p style={styles.statValue}>{users.length}</p>
          </div>

          <div style={styles.statCard}>
            <p style={styles.statLabel}>Transactions All Time</p>
            <p style={styles.statValue}>{stats?.total_transactions_all_time ?? '—'}</p>
          </div>

          <div style={styles.statCard}>
            <p style={styles.statLabel}>Transactions Last 72h</p>
            <p style={styles.statValue}>{stats?.total_transactions_last_72h ?? '—'}</p>
          </div>

          <div style={styles.statCard}>
            <p style={styles.statLabel}>Flagged Anomalies</p>
            <p style={styles.statValue}>{dataQuality?.flagged_count ?? '—'}</p>
          </div>
        </div>
      </div>

      <div style={styles.card}>
        <h2 style={styles.sectionHeader}>System-Wide Transaction Stats</h2>

        {!stats ? (
          <p style={styles.emptyText}>No stats available.</p>
        ) : (
          <div style={styles.statGrid}>
            <div style={styles.statCard}>
              <p style={styles.statLabel}>All Transactions</p>
              <p style={styles.statValue}>{stats.total_transactions_all_time}</p>
            </div>
            <div style={styles.statCard}>
              <p style={styles.statLabel}>Last 72 Hours</p>
              <p style={styles.statValue}>{stats.total_transactions_last_72h}</p>
            </div>
            <div style={styles.statCard}>
              <p style={styles.statLabel}>USD → LBP (72h)</p>
              <p style={styles.statValue}>{stats.usd_to_lbp_last_72h}</p>
            </div>
            <div style={styles.statCard}>
              <p style={styles.statLabel}>LBP → USD (72h)</p>
              <p style={styles.statValue}>{stats.lbp_to_usd_last_72h}</p>
            </div>
          </div>
        )}

        {stats && (
          <div style={{ marginTop: '16px', color: '#6c757d' }}>
            Window: {stats.window_start || '—'} → {stats.window_end || '—'}
          </div>
        )}
      </div>

      <div style={styles.card}>
        <h2 style={styles.sectionHeader}>Users Management</h2>

        {users.length === 0 ? (
          <p style={styles.emptyText}>No users found.</p>
        ) : (
          <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>ID</th>
                  <th style={styles.th}>Username</th>
                  <th style={styles.th}>Current Role</th>
                  <th style={styles.th}>Current Status</th>
                  <th style={styles.th}>Change Status</th>
                  <th style={styles.th}>Change Role</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id}>
                    <td style={styles.td}>{user.id}</td>
                    <td style={styles.td}>{user.user_name}</td>
                    <td style={styles.td}>{renderRoleBadge(user.role)}</td>
                    <td style={styles.td}>{renderStatusBadge(user.status)}</td>
                    <td style={styles.td}>
                      <div style={styles.actionGroup}>
                        <select
                          style={styles.select}
                          value={userEdits[user.id]?.status || user.status}
                          onChange={(e) =>
                            handleUserEditChange(user.id, 'status', e.target.value)
                          }
                        >
                          <option value="ACTIVE">ACTIVE</option>
                          <option value="SUSPENDED">SUSPENDED</option>
                          <option value="BANNED">BANNED</option>
                        </select>
                        <button
                          type="button"
                          style={styles.smallButton}
                          onClick={() => handleUpdateStatus(user.id)}
                          disabled={actionLoadingKey === `status-${user.id}`}
                        >
                          {actionLoadingKey === `status-${user.id}` ? 'Saving...' : 'Save'}
                        </button>
                      </div>
                    </td>
                    <td style={styles.td}>
                      <div style={styles.actionGroup}>
                        <select
                          style={styles.select}
                          value={userEdits[user.id]?.role || user.role}
                          onChange={(e) =>
                            handleUserEditChange(user.id, 'role', e.target.value)
                          }
                        >
                          <option value="USER">USER</option>
                          <option value="ADMIN">ADMIN</option>
                        </select>
                        <button
                          type="button"
                          style={styles.smallButton}
                          onClick={() => handleUpdateRole(user.id)}
                          disabled={actionLoadingKey === `role-${user.id}`}
                        >
                          {actionLoadingKey === `role-${user.id}` ? 'Saving...' : 'Save'}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div style={styles.card}>
        <h2 style={styles.sectionHeader}>Audit Logs Viewer</h2>

        <form onSubmit={applyLogFilters}>
          <div style={styles.filtersGrid}>
            <div style={styles.field}>
              <label style={styles.label}>From</label>
              <input
                type="datetime-local"
                name="from"
                value={logFilters.from}
                onChange={handleLogFilterChange}
                style={styles.input}
              />
            </div>

            <div style={styles.field}>
              <label style={styles.label}>To</label>
              <input
                type="datetime-local"
                name="to"
                value={logFilters.to}
                onChange={handleLogFilterChange}
                style={styles.input}
              />
            </div>

            <div style={styles.field}>
              <label style={styles.label}>Actor User ID</label>
              <input
                type="number"
                name="actor_user_id"
                value={logFilters.actor_user_id}
                onChange={handleLogFilterChange}
                style={styles.input}
              />
            </div>

            <div style={styles.field}>
              <label style={styles.label}>Target User ID</label>
              <input
                type="number"
                name="target_user_id"
                value={logFilters.target_user_id}
                onChange={handleLogFilterChange}
                style={styles.input}
              />
            </div>

            <div style={styles.field}>
              <label style={styles.label}>Event Type</label>
              <input
                type="text"
                name="event_type"
                value={logFilters.event_type}
                onChange={handleLogFilterChange}
                placeholder="Example: TX_CREATE"
                style={styles.input}
              />
            </div>

            <div style={styles.field}>
              <label style={styles.label}>Success</label>
              <select
                name="success"
                value={logFilters.success}
                onChange={handleLogFilterChange}
                style={styles.select}
              >
                <option value="">Any</option>
                <option value="true">True</option>
                <option value="false">False</option>
              </select>
            </div>

            <div style={styles.field}>
              <label style={styles.label}>Limit</label>
              <input
                type="number"
                name="limit"
                value={logFilters.limit}
                onChange={handleLogFilterChange}
                min="1"
                max="200"
                style={styles.input}
              />
            </div>

            <div style={styles.field}>
              <label style={styles.label}>Offset</label>
              <input
                type="number"
                name="offset"
                value={logFilters.offset}
                onChange={handleLogFilterChange}
                min="0"
                style={styles.input}
              />
            </div>
          </div>

          <div style={styles.buttonRow}>
            <button type="submit" style={styles.primaryButton}>
              Apply Log Filters
            </button>
            <button
              type="button"
              style={styles.neutralButton}
              onClick={resetLogFilters}
            >
              Reset Log Filters
            </button>
          </div>
        </form>

        <div style={{ marginTop: '16px', color: '#6c757d' }}>
          Total logs: {logsData?.total ?? 0}
        </div>

        {!Array.isArray(logsData?.logs) || logsData.logs.length === 0 ? (
          <p style={{ ...styles.emptyText, marginTop: '16px' }}>No logs found.</p>
        ) : (
          <div style={{ ...styles.tableWrapper, marginTop: '16px' }}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>ID</th>
                  <th style={styles.th}>Created At</th>
                  <th style={styles.th}>Event</th>
                  <th style={styles.th}>Action</th>
                  <th style={styles.th}>Success</th>
                  <th style={styles.th}>Status Code</th>
                  <th style={styles.th}>Actor</th>
                  <th style={styles.th}>Target</th>
                  <th style={styles.th}>Path</th>
                  <th style={styles.th}>Message</th>
                  <th style={styles.th}>Metadata</th>
                </tr>
              </thead>
              <tbody>
                {logsData.logs.map((log) => (
                  <tr key={log.id}>
                    <td style={styles.td}>{log.id}</td>
                    <td style={styles.td}>{log.created_at || '—'}</td>
                    <td style={styles.td}>{log.event_type || '—'}</td>
                    <td style={styles.td}>{log.action || '—'}</td>
                    <td style={styles.td}>{String(log.success)}</td>
                    <td style={styles.td}>{log.status_code ?? '—'}</td>
                    <td style={styles.td}>{log.actor_user_id ?? '—'}</td>
                    <td style={styles.td}>{log.target_user_id ?? '—'}</td>
                    <td style={styles.td}>{log.path || '—'}</td>
                    <td style={styles.td}>{log.message || '—'}</td>
                    <td style={styles.td}>
                      <pre style={styles.pre}>
                        {log.metadata_json
                          ? JSON.stringify(log.metadata_json, null, 2)
                          : '—'}
                      </pre>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div style={styles.card}>
        <h2 style={styles.sectionHeader}>Data Quality Monitor</h2>

        <form onSubmit={applyQualityFilters}>
          <div style={styles.filtersGrid}>
            <div style={styles.field}>
              <label style={styles.label}>From</label>
              <input
                type="datetime-local"
                name="from"
                value={qualityFilters.from}
                onChange={handleQualityFilterChange}
                style={styles.input}
              />
            </div>

            <div style={styles.field}>
              <label style={styles.label}>To</label>
              <input
                type="datetime-local"
                name="to"
                value={qualityFilters.to}
                onChange={handleQualityFilterChange}
                style={styles.input}
              />
            </div>

            <div style={styles.field}>
              <label style={styles.label}>Direction</label>
              <select
                name="direction"
                value={qualityFilters.direction}
                onChange={handleQualityFilterChange}
                style={styles.select}
              >
                <option value="">All</option>
                <option value="usd_to_lbp">USD to LBP</option>
                <option value="lbp_to_usd">LBP to USD</option>
              </select>
            </div>
          </div>

          <div style={styles.buttonRow}>
            <button type="submit" style={styles.primaryButton}>
              Apply Quality Filters
            </button>
            <button
              type="button"
              style={styles.neutralButton}
              onClick={resetQualityFilters}
            >
              Reset Quality Filters
            </button>
          </div>
        </form>

        {!dataQuality ? (
          <p style={{ ...styles.emptyText, marginTop: '16px' }}>No data quality report available.</p>
        ) : (
          <>
            <div style={{ ...styles.statGrid, marginTop: '18px' }}>
              <div style={styles.statCard}>
                <p style={styles.statLabel}>Source</p>
                <p style={{ ...styles.statValue, fontSize: '20px' }}>
                  {dataQuality.source || '—'}
                </p>
              </div>

              <div style={styles.statCard}>
                <p style={styles.statLabel}>Transactions Checked</p>
                <p style={styles.statValue}>{dataQuality.total_transactions ?? 0}</p>
              </div>

              <div style={styles.statCard}>
                <p style={styles.statLabel}>Flagged Count</p>
                <p style={styles.statValue}>{dataQuality.flagged_count ?? 0}</p>
              </div>

              <div style={styles.statCard}>
                <p style={styles.statLabel}>Threshold %</p>
                <p style={styles.statValue}>{dataQuality.anomaly_threshold_percent ?? '—'}</p>
              </div>
            </div>

            <div style={{ marginTop: '16px', color: '#6c757d' }}>
              Counts by direction:
              {' '}
              USD→LBP {dataQuality?.counts_by_direction?.usd_to_lbp ?? 0}
              {' | '}
              LBP→USD {dataQuality?.counts_by_direction?.lbp_to_usd ?? 0}
            </div>

            {anomalyRows.length === 0 ? (
              <p style={{ ...styles.emptyText, marginTop: '16px' }}>No anomalies found.</p>
            ) : (
              <div style={{ ...styles.tableWrapper, marginTop: '16px' }}>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      <th style={styles.th}>Transaction ID</th>
                      <th style={styles.th}>Direction</th>
                      <th style={styles.th}>Rate</th>
                      <th style={styles.th}>Deviation %</th>
                      <th style={styles.th}>Baseline Avg</th>
                      <th style={styles.th}>Created At</th>
                    </tr>
                  </thead>
                  <tbody>
                    {anomalyRows.map((item) => (
                      <tr key={`${item.transaction_id}-${item.created_at}`}>
                        <td style={styles.td}>{item.transaction_id}</td>
                        <td style={styles.td}>{item.direction}</td>
                        <td style={styles.td}>{item.rate}</td>
                        <td style={styles.td}>{item.deviation_percent}</td>
                        <td style={styles.td}>{item.baseline_avg_rate}</td>
                        <td style={styles.td}>{item.created_at || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>

      <div style={styles.card}>
        <h2 style={styles.sectionHeader}>Backup & Restore</h2>

        <div style={styles.buttonRow}>
          <button
            type="button"
            onClick={handleCreateBackup}
            disabled={backupLoading}
            style={styles.primaryButton}
          >
            {backupLoading ? 'Creating Backup...' : 'Create Backup'}
          </button>
          <button
            type="button"
            onClick={handleRestoreBackup}
            disabled={restoreLoading}
            style={styles.dangerButton}
          >
            {restoreLoading ? 'Restoring...' : 'Restore from Backup'}
          </button>
          <button
            type="button"
            onClick={fetchBackupStatus}
            disabled={statusLoading}
            style={styles.neutralButton}
          >
            {statusLoading ? 'Loading...' : 'Refresh Status'}
          </button>
        </div>

        {backupStatus && (
          <div style={{ marginTop: '16px', padding: '12px', backgroundColor: '#f8f9fa', borderRadius: '8px' }}>
            <h3 style={{ margin: '0 0 8px 0', fontSize: '16px' }}>Backup Status</h3>
            <p style={{ margin: '4px 0' }}>Last Backup: {backupStatus.last_backup || 'None'}</p>
            <p style={{ margin: '4px 0' }}>Available Backups: {backupStatus.available_backups || 0}</p>
            <p style={{ margin: '4px 0' }}>Total Size: {backupStatus.total_size || 'Unknown'}</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminPage;