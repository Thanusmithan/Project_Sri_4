// src/ForgotPassword.js
import React, { useState } from 'react';
import './Css/ForgotPassword.css';
import Header from './Componets/Header_Signup';
import Footer from './Componets/Footer';
import Alert from './Alert';

const ForgotPassword = () => {
    const [email, setEmail] = useState('');
    const [alert, setAlert] = useState(null); // State for alert
    const [isSubmitting, setIsSubmitting] = useState(false); // Loading state

    // Helper function to show alert with automatic dismissal
    const showAlert = (message, type) => {
        setAlert({ message, type });
        setTimeout(() => setAlert(null), 3000); // Close alert after 3 seconds
    };

    const handleSubmit = (e) => {
        e.preventDefault();

        // Validate email
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailPattern.test(email)) {
            showAlert('Please enter a valid email address', 'error');
            return;
        }

        // Simulate API request
        setIsSubmitting(true);
        setTimeout(() => {
            showAlert('Password reset link sent! Check your email.', 'success');
            setIsSubmitting(false);
            setEmail(''); // Clear email field after submission
        }, 2000);
    };

    return (
        <>
            <Header />

            <div className="forgot-page-wrapper">

                <br />
                <div className="forgot-password-wrapper">
                    <h1>Forgot Password</h1>
                    <p className="subtitle">Enter your email address to receive a password reset link.</p>
                    <form onSubmit={handleSubmit} className="form-container">
                        <input
                            type="email"
                            placeholder="Email Address"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            className="forgot-input-field"
                            required
                            aria-label="Email Address"
                        />
                        <button type="submit" className="btn-submit forgot-password-btn" disabled={isSubmitting}>
                            {isSubmitting ? 'Sending...' : 'Send Reset Link'}
                        </button>
                    </form>
                    {alert && <Alert message={alert.message} type={alert.type} onClose={() => setAlert(null)} />}
                </div>

            </div>
            <Footer />
        </>
    );
};

export default ForgotPassword;
