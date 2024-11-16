import React from 'react';
import './Css/Contact.css';
import { Container, Row, Col, Form, Button } from 'react-bootstrap';
import Header from './Componets/Header_Login';
import Footer from './Componets/Footer'
import hero_bg_img from './Images/Hero-bg-img.jpg'; // Use the same or different image


const Contact = () => {
    return (
        <div className="contact-page">
            {/* Header */}
            <Header />
            {/* Hero Section */}
            <section className="hero-section">
                <Container>
                    <Row className="align-items-center">
                        <Col md={6}>
                            <div className="hero-content">
                                <h1>Contact Us</h1>
                                <p>
                                    We would love to hear from you! Please reach out with any
                                    inquiries or to schedule an appointment.
                                </p>
                            </div>
                        </Col>
                        <Col md={6}>
                            <img src={hero_bg_img} alt="Contact Us" className="contact-img" />
                        </Col>
                    </Row>
                </Container>
            </section>

            {/* Contact Form Section */}
            <section className="contact-form-section">
                <Container>
                    <Row>
                        <Col md={12}>
                            <h2 className="form-title">Get in Touch</h2>
                            <Form>
                                <Form.Group controlId="formName">
                                    <Form.Label>Name</Form.Label>
                                    <Form.Control type="text" placeholder="Enter your name" className='inputs' />
                                </Form.Group>

                                <Form.Group controlId="formEmail" className='mt-3'>
                                    <Form.Label>Email</Form.Label>
                                    <Form.Control type="email" placeholder="Enter your email" className='inputs' />
                                </Form.Group>

                                <Form.Group controlId="formMessage" className='mt-3'>
                                    <Form.Label>Message</Form.Label>
                                    <Form.Control as="textarea" rows={3} placeholder="Your message" className='inputs' />
                                </Form.Group>

                                <Button variant="success" type="submit" className='mt-3'>
                                    Send Message
                                </Button>
                            </Form>
                        </Col>
                    </Row>
                </Container>
            </section>

            {/* Footer */}
            <Footer />
        </div>
    );
};

export default Contact;
