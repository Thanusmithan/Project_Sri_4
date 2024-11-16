// src/Alert.js
import React from 'react';
import './Css/Alert.css'; // Make sure to create this CSS file

const Alert = ({ message, type, onClose }) => {
    return (
        <div className={`alert ${type}`} onClick={onClose}>
            {message}
            <span className="close-btn" onClick={onClose}>&times;</span>
        </div>
    );
};

export default Alert;
