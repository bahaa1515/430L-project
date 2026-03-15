import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';

const ProofPanel = () => {
  const [currentTime, setCurrentTime] = useState(new Date());
  const location = useLocation();

  // Update time every second
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const formatTime = (date) => {
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
    });
  };

  return (
    <div
      style={{
        backgroundColor: '#f0f0f0',
        border: '2px solid #333',
        borderRadius: '8px',
        padding: '12px',
        marginBottom: '20px',
        fontFamily: 'monospace',
        fontSize: '14px',
        lineHeight: '1.6',
      }}
    >
      <div>
        <strong>Full Name:</strong> Bahaa Hamdan
      </div>
      <div>
        <strong>Current Browser Time:</strong> {formatTime(currentTime)}
      </div>
      <div>
        <strong>Current Route:</strong> {location.pathname}
      </div>
    </div>
  );
};

export default ProofPanel;
