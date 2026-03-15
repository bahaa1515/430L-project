import React from 'react';

const TransactionsTable = ({ transactions, loading, error }) => {
  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '20px' }}>
        Loading transactions...
      </div>
    );
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

  if (!transactions || transactions.length === 0) {
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
        No transactions found
      </div>
    );
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table
        style={{
          width: '100%',
          borderCollapse: 'collapse',
          backgroundColor: '#fff',
          borderRadius: '8px',
          overflow: 'hidden',
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
        }}
      >
        <thead>
          <tr style={{ backgroundColor: '#34495e', color: '#fff' }}>
            <th style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #2c3e50' }}>ID</th>
            <th style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #2c3e50' }}>USD Amount</th>
            <th style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #2c3e50' }}>LBP Amount</th>
            <th style={{ padding: '12px', textAlign: 'left', borderBottom: '2px solid #2c3e50' }}>Direction</th>
          </tr>
        </thead>
        <tbody>
          {transactions.map((transaction, index) => {
            const direction =
              transaction.usd_to_lbp === true
                ? 'USD to LBP'
                : transaction.usd_to_lbp === false
                ? 'LBP to USD'
                : 'Unknown';

            return (
              <tr
                key={index}
                style={{
                  backgroundColor: index % 2 === 0 ? '#f8f9fa' : '#fff',
                  borderBottom: '1px solid #e9ecef',
                }}
              >
                <td style={{ padding: '12px', textAlign: 'left' }}>
                  {transaction.id || `TX-${index + 1}`}
                </td>
                <td style={{ padding: '12px', textAlign: 'left', fontWeight: 'bold' }}>
                  {transaction.usd_amount}
                </td>
                <td style={{ padding: '12px', textAlign: 'left', fontWeight: 'bold' }}>
                  {transaction.lbp_amount}
                </td>
                <td style={{ padding: '12px', textAlign: 'left' }}>
                  {direction}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default TransactionsTable;
