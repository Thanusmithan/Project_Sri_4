import React from 'react';
import '../Css/Header.css';
import logo from '../Images/logo.svg';
import { Link } from 'react-router-dom';
import { Container, Row, Col, Button } from 'react-bootstrap';

const Header = () => {
    return (
        <header className="homepage-header">
            <Container>
                <Row className="d-flex justify-content-center">
                    <Col md={3}>
                        <div className="logo">
                            <img src={logo} alt="Ayurvedic Medical Hospital" />
                        </div>
                    </Col>
                    <Col md={9}>
                        <nav className="nav-links">
                            <Link to="/patient_dashboard" aria-label="Home Page" className='ms-l-20'>Dashboard</Link>
                            <Link to="/patient_appointment" aria-label="Services Page" className='ms-l-20'>Appointments</Link>
                            <Link to="/patient_services" aria-label="Services Page" className='ms-l-20'>Services</Link>
                            <Link to="/patient_messages" aria-label="Services Page" className='ms-l-20'>Messages</Link>
                            <Link to="/patient_review" aria-label="Services Page" className='ms-l-20 me-r-20'>Ratings</Link>
                            <Button variant='secondary' className='patient-logout-btn'>
                                <Link to="/Login" aria-label="About us Page" className=''>Log Out</Link>
                            </Button>
                        </nav>
                    </Col>
                </Row>
            </Container>
        </header>
    );
};

export default Header;
