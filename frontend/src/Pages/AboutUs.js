import React from 'react';
import './Css/AboutUs.css';
import { Container, Row, Col } from 'react-bootstrap';
import hero_bg_img from './Images/Hero-bg-img.jpg'; // Use a different image or the same one for now
import Header from './Componets/Header_Login';
import Footer from './Componets/Footer'

const AboutUs = () => {
    return (
        <div className="about-us-page">
            {/* Header */}
            <Header />
            {/* Hero Section */}
            <section className="hero-section">
                <Container>
                    <Row className="align-items-center">
                        <Col md={6}>
                            <div className="hero-content">
                                <h1>About Us</h1>
                                <p>
                                    At Ayurvedic Medical Hospital, we are committed to providing the best
                                    Ayurvedic care and holistic healing. Our experienced practitioners
                                    focus on personalized treatment plans to meet the unique needs of
                                    every patient.
                                </p>
                            </div>
                        </Col>
                        <Col md={6}>
                            <img src={hero_bg_img} alt="About Us" className="about-img" />
                        </Col>
                    </Row>
                </Container>
            </section>

            {/* Mission and Vision Section */}
            <section className="mission-vision-section">
                <Container>
                    <Row>
                        <Col md={6}>
                            <h2 className="section-title">Our Mission</h2>
                            <p>
                                To provide high-quality Ayurvedic treatments that enhance the overall well-being
                                of our patients while preserving the traditions and principles of Ayurveda.
                            </p>
                        </Col>
                        <Col md={6}>
                            <h2 className="section-title">Our Vision</h2>
                            <p>
                                To be recognized as a leading Ayurvedic medical facility, promoting health
                                and wellness through natural healing practices.
                            </p>
                        </Col>
                    </Row>
                </Container>
            </section>

            {/* Footer */}
            <Footer/>
        </div>
    );
};

export default AboutUs;
