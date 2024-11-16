//Services.js
import React from 'react';
import './Css/Services.css';
import { Container, Row, Col } from 'react-bootstrap';
import hero_bg_img from './Images/Hero-bg-img.jpg'; // Use the same or different image
import Header from './Componets/Header_Login';
import Footer from './Componets/Footer'


const Services = () => {
    return (
        <div className="services-page">
            {/* Header */}
            <Header />
            {/* Hero Section */}
            <section className="hero-section">
                <Container>
                    <Row className="align-items-center">
                        <Col md={6}>
                            <div className="hero-content">
                                <h1>Our Services</h1>
                                <p>
                                    We offer a wide range of Ayurvedic services to cater to the
                                    holistic needs of our patients. Explore our services below.
                                </p>
                            </div>
                        </Col>
                        <Col md={6}>
                            <img src={hero_bg_img} alt="Our Services" className="services-img" />
                        </Col>
                    </Row>
                </Container>
            </section>

            {/* Services List */}
            <section className="services-list-section">
                <Container>
                    <Row>
                        <Col md={4}>
                            <h2 className="service-title">Consultation</h2>
                            <p>Personalized Ayurvedic consultations tailored to your health needs.</p>
                        </Col>
                        <Col md={4}>
                            <h2 className="service-title">Panchakarma</h2>
                            <p>Detoxification therapies designed to cleanse the body and rejuvenate.</p>
                        </Col>
                        <Col md={4}>
                            <h2 className="service-title">Herbal Treatments</h2>
                            <p>Natural herbal remedies to support your health and well-being.</p>
                        </Col>
                    </Row>
                </Container>
            </section>

            {/* Footer */}
            <Footer />
        </div>
    );
};

export default Services;
