// SignUp.js code -- After backend initialization
// SignUp.js
import React, { useState } from 'react';
import './Css/SignUp.css';
import Header from './Componets/Header_Login';
import Footer from './Componets/Footer';
import Alert from './Alert';

const SignUp = () => {
    const [firstName, setFirstName] = useState('');
    const [lastName, setLastName] = useState('');
    const [email, setEmail] = useState('');
    const [phone, setPhone] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [alert, setAlert] = useState(null);

    const showAlert = (message, type) => {
        setAlert({ message, type });
        setTimeout(() => setAlert(null), 3000);
    };

    const validateEmail = (email) => /\S+@\S+\.\S+/.test(email);
    const validatePhone = (phone) => /^\d{10}$/.test(phone);

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (password !== confirmPassword) {
            showAlert("Passwords do not match!", "error");
            return;
        }
        if (!validateEmail(email)) {
            showAlert("Please enter a valid email address!", "error");
            return;
        }
        if (!validatePhone(phone)) {
            showAlert("Please enter a valid 10-digit phone number!", "error");
            return;
        }

        setIsSubmitting(true);

        try {
            const response = await fetch("http://localhost:5000/api/auth/signup", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ firstName, lastName, email, phone, password }),
            });

            const data = await response.json();

            if (response.ok) {
                showAlert("Signup successful! Redirecting to login...", "success");
                setTimeout(() => window.location.href = "/login", 2000);
            } else {
                showAlert(data.message || "Signup failed. Please try again.", "error");
            }
        } catch (error) {
            console.error("Error during signup:", error);
            showAlert("Server error. Please try again later.", "error");
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <div className="signup-page-wrapper">
            <Header />
            <br />
            <div className="signup-wrapper">
                <div className="signup-left">
                    <div className="signup-content">
                        <h1>Create Your Account</h1>
                        <p className="subtitle">Please fill in the details below</p>
                        <form onSubmit={handleSubmit} className="form-container">
                            <input
                                type="text"
                                placeholder="Enter your first name"
                                value={firstName}
                                onChange={(e) => setFirstName(e.target.value)}
                                className="input-field"
                                required
                            />
                            <input
                                type="text"
                                placeholder="Enter your last name"
                                value={lastName}
                                onChange={(e) => setLastName(e.target.value)}
                                className="input-field"
                                required
                            />
                            <input
                                type="email"
                                placeholder="Enter your email address"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                className="input-field"
                                required
                            />
                            <input
                                type="tel"
                                placeholder="Enter your 10-digit phone number"
                                value={phone}
                                onChange={(e) => setPhone(e.target.value)}
                                className="input-field"
                                required
                            />
                            <input
                                type="password"
                                placeholder="Create a password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="input-field"
                                required
                            />
                            <input
                                type="password"
                                placeholder="Confirm your password"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                className="input-field"
                                required
                            />
                            <button type="submit" className="btn-signup login-btn mt-2" disabled={isSubmitting}>
                                {isSubmitting ? "Signing up..." : "Sign Up"}
                            </button>
                        </form>
                        <div className="login-link">
                            <p>Already have an account? <a href="/login">Login</a></p>
                        </div>
                        <div className="support-info">
                            <p>Need help? Contact our support team</p>
                            <a href="mailto:support@ayurved.com" className="support-email">support@ayurved.com</a>
                        </div>
                    </div>
                </div>
                <div className="signup-right">
                    <div className="signup-right-content text-bg-light opacity-30">
                        <h2>Nature Medicine</h2>
                        <p>The new gold standard for cancer treatment. This interactive report includes updated information about approved or investigational treatments for each patient.</p>
                    </div>
                </div>
            </div>
            <br />
            {alert && <Alert message={alert.message} type={alert.type} />}
            <Footer />
        </div>
    );
};

export default SignUp;
