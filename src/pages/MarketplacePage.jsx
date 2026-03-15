import React, { useEffect, useState } from 'react';
import apiClient from '../api/apiClient';
import ErrorAlert from '../components/ErrorAlert';
import ProofPanel from '../components/ProofPanel';
import { useAuth } from '../context/AuthContext';

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
  successButton: {
    backgroundColor: '#17a2b8',
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
  badgeMine: {
    display: 'inline-block',
    marginLeft: '8px',
    padding: '3px 8px',
    backgroundColor: '#e8f0fe',
    color: '#1a73e8',
    borderRadius: '999px',
    fontSize: '12px',
    fontWeight: '600',
  },
};

const MarketplacePage = () => {
  const { userId } = useAuth();

  const [offers, setOffers] = useState([]);
  const [trades, setTrades] = useState([]);
  const [pageLoading, setPageLoading] = useState(true);
  const [offersLoading, setOffersLoading] = useState(false);
  const [tradesLoading, setTradesLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [acceptCooldown, setAcceptCooldown] = useState(false);
  const [acceptCountdown, setAcceptCountdown] = useState(0);
  const [createCooldown, setCreateCooldown] = useState(false);
  const [createCountdown, setCreateCountdown] = useState(0);

  const [formData, setFormData] = useState({
    give_currency: 'USD',
    give_amount: '',
    want_currency: 'LBP',
    want_amount: '',
  });

  useEffect(() => {
    initializePage();
  }, []);

  useEffect(() => {
    if (acceptCooldown <= 0) return;

    const timer = setInterval(() => {
      setAcceptCooldown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [acceptCooldown]);

  const getErrorMessage = (err, fallback) =>
    err?.response?.data?.error ||
    err?.response?.data?.message ||
    err?.message ||
    fallback;

  const formatDateTime = (value) => {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
  };

  const initializePage = async () => {
    setPageLoading(true);
    setError('');
    await Promise.all([fetchOffers(), fetchTrades()]);
    setPageLoading(false);
  };

  const fetchOffers = async () => {
    setOffersLoading(true);
    try {
      const response = await apiClient.get('/market/offers', {
        params: { include_mine: true },
      });
      setOffers(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to load offers'));
    } finally {
      setOffersLoading(false);
    }
  };

  const fetchTrades = async () => {
    setTradesLoading(true);
    try {
      const response = await apiClient.get('/market/trades');
      setTrades(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to load trades'));
    } finally {
      setTradesLoading(false);
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;

    setFormData((prev) => {
      const updated = { ...prev, [name]: value };

      if (name === 'give_currency') {
        updated.want_currency = value === 'USD' ? 'LBP' : 'USD';
      }

      if (name === 'want_currency') {
        updated.give_currency = value === 'USD' ? 'LBP' : 'USD';
      }

      return updated;
    });
  };

  const validateForm = () => {
    const giveAmount = Number(formData.give_amount);
    const wantAmount = Number(formData.want_amount);

    if (
      !formData.give_currency ||
      !formData.want_currency ||
      formData.give_amount === '' ||
      formData.want_amount === ''
    ) {
      return 'All fields are required';
    }

    if (formData.give_currency === formData.want_currency) {
      return 'Give currency and want currency must be different';
    }

    if (Number.isNaN(giveAmount) || giveAmount <= 0) {
      return 'Give amount must be a positive number';
    }

    if (Number.isNaN(wantAmount) || wantAmount <= 0) {
      return 'Want amount must be a positive number';
    }

    return '';
  };

  const handleCreateOffer = async (e) => {
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
      await apiClient.post('/market/offers', {
        give_currency: formData.give_currency,
        give_amount: Number(formData.give_amount),
        want_currency: formData.want_currency,
        want_amount: Number(formData.want_amount),
      });

      setSuccessMessage('Offer created successfully');
      setFormData({
        give_currency: 'USD',
        give_amount: '',
        want_currency: 'LBP',
        want_amount: '',
      });

      await fetchOffers();
      await fetchTrades();
    } catch (err) {
      if (err?.response?.status === 429) {
        setError('Too many requests. Please wait before creating another offer.');
        startCreateCooldown(15);
      } else {
        setError(getErrorMessage(err, 'Failed to create offer'));
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleAcceptOffer = async (offerId) => {
    setError('');
    setSuccessMessage('');

    try {
      await apiClient.post(`/market/offers/${offerId}/accept`);
      setSuccessMessage(`Offer #${offerId} accepted successfully`);
      await fetchOffers();
      await fetchTrades();
    } catch (err) {
      if (err?.response?.status === 429) {
        setError('Too many requests. Please wait before accepting another offer.');
        startAcceptCooldown(15);
      } else {
        setError(getErrorMessage(err, 'Failed to accept offer'));
      }
      await fetchOffers();
      await fetchTrades();
    }
  };

  const handleCancelOffer = async (offerId) => {
    setError('');
    setSuccessMessage('');

    try {
      await apiClient.delete(`/market/offers/${offerId}`);
      setSuccessMessage(`Offer #${offerId} cancelled successfully`);
      await fetchOffers();
      await fetchTrades();
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to cancel offer'));
      await fetchOffers();
      await fetchTrades();
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

  const startAcceptCooldown = (seconds) => {
    setAcceptCooldown(true);
    setAcceptCountdown(seconds);
    const interval = setInterval(() => {
      setAcceptCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(interval);
          setAcceptCooldown(false);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
  };

  if (pageLoading) {
    return (
      <div style={styles.page}>
        <ProofPanel />
        <h1>Marketplace</h1>
        <p>Loading marketplace...</p>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <ProofPanel />

      <h1>Marketplace</h1>
      <p style={styles.subtitle}>
        Create offers, browse open offers, accept available offers, and review your trade history.
      </p>

      {error && <ErrorAlert message={error} />}
      {successMessage && <div style={styles.successMessage}>{successMessage}</div>}

      <section style={styles.card}>
        <h2 style={styles.sectionHeader}>Create Offer</h2>

        <form onSubmit={handleCreateOffer}>
          <div style={styles.grid}>
            <div style={styles.field}>
              <label htmlFor="give_currency" style={styles.label}>Give Currency</label>
              <select
                id="give_currency"
                name="give_currency"
                value={formData.give_currency}
                onChange={handleChange}
                style={styles.input}
              >
                <option value="USD">USD</option>
                <option value="LBP">LBP</option>
              </select>
            </div>

            <div style={styles.field}>
              <label htmlFor="give_amount" style={styles.label}>Give Amount</label>
              <input
                id="give_amount"
                name="give_amount"
                type="number"
                min="0"
                step="any"
                value={formData.give_amount}
                onChange={handleChange}
                placeholder="Enter amount"
                style={styles.input}
              />
            </div>

            <div style={styles.field}>
              <label htmlFor="want_currency" style={styles.label}>Want Currency</label>
              <select
                id="want_currency"
                name="want_currency"
                value={formData.want_currency}
                onChange={handleChange}
                style={styles.input}
              >
                <option value="USD">USD</option>
                <option value="LBP">LBP</option>
              </select>
            </div>

            <div style={styles.field}>
              <label htmlFor="want_amount" style={styles.label}>Want Amount</label>
              <input
                id="want_amount"
                name="want_amount"
                type="number"
                min="0"
                step="any"
                value={formData.want_amount}
                onChange={handleChange}
                placeholder="Enter amount"
                style={styles.input}
              />
            </div>
          </div>

          <div style={styles.buttonRow}>
            <button type="submit" disabled={submitting || createCooldown} style={styles.primaryButton}>
              {submitting ? 'Creating...' : createCooldown ? `Try again in ${createCountdown}s` : 'Create Offer'}
            </button>
          </div>
        </form>
      </section>

      <section style={styles.card}>
        <div style={styles.topRow}>
          <h2 style={styles.sectionHeader}>Open Offers</h2>
          <button type="button" onClick={fetchOffers} disabled={offersLoading} style={styles.secondaryButton}>
            {offersLoading ? 'Refreshing...' : 'Refresh Offers'}
          </button>
        </div>

        {offers.length === 0 ? (
          <p>No open offers found.</p>
        ) : (
          <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>ID</th>
                  <th style={styles.th}>Creator</th>
                  <th style={styles.th}>Give</th>
                  <th style={styles.th}>Want</th>
                  <th style={styles.th}>Status</th>
                  <th style={styles.th}>Created At</th>
                  <th style={styles.th}>Action</th>
                </tr>
              </thead>
              <tbody>
                {offers.map((offer) => {
                  const isMine = Number(offer.creator_user_id) === Number(userId);
                  const acceptDisabled = isMine || acceptCooldown || offer.status !== 'OPEN';
                  const cancelDisabled = !isMine || offer.status !== 'OPEN';

                  return (
                    <tr key={offer.id}>
                      <td style={styles.td}>{offer.id}</td>
                      <td style={styles.td}>
                        {offer.creator_user_id}
                        {isMine && <span style={styles.badgeMine}>You</span>}
                      </td>
                      <td style={styles.td}>{offer.give_amount} {offer.give_currency}</td>
                      <td style={styles.td}>{offer.want_amount} {offer.want_currency}</td>
                      <td style={styles.td}>{offer.status}</td>
                      <td style={styles.td}>{formatDateTime(offer.created_at)}</td>
                      <td style={styles.td}>
                        {isMine ? (
                          <button
                            type="button"
                            onClick={() => handleCancelOffer(offer.id)}
                            disabled={cancelDisabled}
                            style={styles.dangerButton}
                          >
                            Cancel
                          </button>
                        ) : (
                          <button
                            type="button"
                            onClick={() => handleAcceptOffer(offer.id)}
                            disabled={acceptDisabled}
                            style={styles.successButton}
                            title={acceptCooldown ? `Wait ${acceptCountdown}s before trying again` : ''}
                          >
                            {acceptCooldown ? `Wait ${acceptCountdown}s` : 'Accept'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <div style={styles.helperText}>
          You cannot accept your own offer. Your own offers show a cancel button instead.
        </div>
      </section>

      <section style={styles.card}>
        <div style={styles.topRow}>
          <h2 style={styles.sectionHeader}>My Trades</h2>
          <button type="button" onClick={fetchTrades} disabled={tradesLoading} style={styles.secondaryButton}>
            {tradesLoading ? 'Refreshing...' : 'Refresh Trades'}
          </button>
        </div>

        {trades.length === 0 ? (
          <p>No trades yet.</p>
        ) : (
          <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Trade ID</th>
                  <th style={styles.th}>Offer ID</th>
                  <th style={styles.th}>Buyer User ID</th>
                  <th style={styles.th}>Seller User ID</th>
                  <th style={styles.th}>Created At</th>
                </tr>
              </thead>
              <tbody>
                {trades.map((trade) => (
                  <tr key={trade.id}>
                    <td style={styles.td}>{trade.id}</td>
                    <td style={styles.td}>{trade.offer_id}</td>
                    <td style={styles.td}>{trade.buyer_user_id}</td>
                    <td style={styles.td}>{trade.seller_user_id}</td>
                    <td style={styles.td}>{formatDateTime(trade.created_at)}</td>
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

export default MarketplacePage;