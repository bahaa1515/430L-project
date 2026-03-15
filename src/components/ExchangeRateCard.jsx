import React from 'react';
import SummaryCard from './SummaryCard';
import LoadingSpinner from './LoadingSpinner';

const ExchangeRateCard = ({ rate, loading, error }) => {
  if (loading) {
    return <LoadingSpinner />;
  }

  if (error) {
    return (
      <div
        style={{
          backgroundColor: '#f8d7da',
          padding: '16px',
          borderRadius: '8px',
          color: '#721c24',
          textAlign: 'center',
        }}
      >
        {error}
      </div>
    );
  }

  if (!rate || (!rate.usd_to_lbp && !rate.lbp_to_usd)) {
    return (
      <div
        style={{
          backgroundColor: '#e9ecef',
          padding: '16px',
          borderRadius: '8px',
          color: '#6c757d',
          textAlign: 'center',
        }}
      >
        No exchange rate data available
      </div>
    );
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
      {rate.usd_to_lbp && (
        <SummaryCard
          title="USD to LBP"
          value={rate.usd_to_lbp.toFixed(2)}
          subtitle="Current rate"
          color="#27ae60"
        />
      )}
      {rate.lbp_to_usd && (
        <SummaryCard
          title="LBP to USD"
          value={rate.lbp_to_usd.toFixed(4)}
          subtitle="Current rate"
          color="#3498db"
        />
      )}
    </div>
  );
};

export default ExchangeRateCard;
