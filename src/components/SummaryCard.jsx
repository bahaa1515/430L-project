import React from 'react';

const SummaryCard = ({ title, value, subtitle, color = '#3498db' }) => {
  return (
    <div
      style={{
        backgroundColor: '#fff',
        border: `2px solid ${color}`,
        borderRadius: '8px',
        padding: '20px',
        textAlign: 'center',
        boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
      }}
    >
      <h3 style={{ margin: '0 0 8px 0', color: '#555', fontSize: '14px', textTransform: 'uppercase' }}>
        {title}
      </h3>
      <div style={{ fontSize: '28px', fontWeight: 'bold', color, margin: '8px 0' }}>
        {value}
      </div>
      {subtitle && (
        <p style={{ margin: '8px 0 0 0', color: '#888', fontSize: '12px' }}>
          {subtitle}
        </p>
      )}
    </div>
  );
};

export default SummaryCard;
