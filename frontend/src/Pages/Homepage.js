import React from 'react';
import './Css/Homepage.css';
import hero_img from './Images/Hero-img.webp';
import hero_bg_img from './Images/Hero-bg-img.jpg';
import { Link } from 'react-router-dom';
import Header from './Componets/Header_Signup';
import Footer from './Componets/Footer';
import { Container, Row, Col, Button } from 'react-bootstrap';


const Home = () => {
    return (
        <div className="homepage">
            {/* Header */}
            <Header/>
            {/* Hero Section */}
            <section className="hero-section">
                <Container>
                    <Row className="align-items-center">
                        <Col md={6}>
                            <div className="hero-content">
                                <h1>Welcome to Sri Kirishna Ayurvedic Medical Hospital</h1>
                                <p>Experience holistic healing with time-tested Ayurvedic practices.</p>
                                {/* Button Group */}
                                <div className="d-flex justify-content-start gap-3">
                                    <Button variant="primary" className="login-homepage-btn" as={Link} to="/Login" aria-label="Login">Log In</Button>
                                    {/* <Button variant="success" className="hero-btn" as={Link} to="/patient_appointment" aria-label="Book Appointment">Book Appointment</Button> */}
                                </div>

                            </div>
                        </Col>
                        <Col md={6}>
                            <img src={hero_img} alt="Ayurvedic Healing" className="hero-img" />
                        </Col>
                    </Row>
                </Container>
            </section>

            {/* Services Section */}
            <section className="services-section">
                <Container>
                    <h2 className="home-section-title">Our Services</h2>
                    <div className="home-heading-underline"></div> {/* Add this line for the underline */}
                    <Row>
                        <Col md={4}>
                            <div className="service-card">
                                <h3>Panchakarma Therapy</h3>
                                <p>Detoxify your body with expert-led Panchakarma treatments.</p>
                            </div>
                        </Col>
                        <Col md={4}>
                            <div className="service-card">
                                <h3>Herbal Medicine</h3>
                                <p>Personalized herbal solutions for your health concerns.</p>
                            </div>
                        </Col>
                        <Col md={4}>
                            <div className="service-card">
                                <h3>Yoga & Meditation</h3>
                                <p>Achieve mental peace with Yoga and Meditation sessions.</p>
                            </div>
                        </Col>
                    </Row>
                </Container>
            </section>

            {/* About Us Section */}
            <section className="about-us-section">
                <Container>
                    <Row className="align-items-center">
                        <Col md={6}>
                            <h2 className="home-section-title">About Us</h2>
                            <div className="home-heading-underline"></div> {/* Add this line for the underline */}
                            <p>
                                Ayurvedic Medical Hospital is dedicated to offering traditional Ayurvedic
                                treatments to enhance your well-being. Our team of certified practitioners
                                focuses on holistic health and personalized treatments for each patient.
                            </p>
                        </Col>
                        <Col md={6}>
                            <img src={hero_bg_img} alt="About Us" className="about-img" />
                        </Col>
                    </Row>
                </Container>
            </section>

            {/* Testimonials Section */}
            <section className="testimonials-section">
                <Container>
                    <h2 className="home-section-title mb-2">What Our Patients Say</h2>
                    <div className="home-heading-underline"></div> {/* Add this line for the underline */}
                    <Row>
                        <Col md={4}>
                            <blockquote className="testimonial">
                                “The Ayurvedic treatments here have changed my life. Highly recommend!”
                                <footer>- Patient A</footer>
                            </blockquote>
                        </Col>
                        <Col md={4}>
                            <blockquote className="testimonial">
                                “Amazing experience! Panchakarma therapy rejuvenated my health.”
                                <footer>- Patient B</footer>
                            </blockquote>
                        </Col>
                        <Col md={4}>
                            <blockquote className="testimonial">
                                “The yoga sessions have brought peace to my life. Incredible staff!”
                                <footer>- Patient C</footer>
                            </blockquote>
                        </Col>
                    </Row>
                </Container>
            </section>

            {/* Footer */}
            <Footer/>
        </div>
    );
};

export default Home;
