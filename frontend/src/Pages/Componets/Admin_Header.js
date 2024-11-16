import React from 'react';
import '../Css/Admin_Header.css';
import logo from '../Images/logo.svg';
import { Link } from 'react-router-dom';
import { Container, Row, Col, Button } from 'react-bootstrap';

const Header = () => {
    return (
        <header className="homepage-header">
            <Container>
                <Row className="d-flex justify-content-center">
                    <Col md={3}>
                        <div className="admin-logo">
                            <img src={logo} alt="Ayurvedic Medical Hospital" />
                        </div>
                    </Col>
                    <Col md={9}>
                        <nav className="admin-nav-links">
                            <Link to="/admin_dashboard" aria-label="Home Page" className="ms-l-20">Dashboard</Link>
                            <Link to="/admin_appointment" aria-label="Appointment Page" className="ms-l-20">Appointments</Link>
                            <Link to="/admin_services" aria-label="Services Page" className="ms-l-20">Services</Link>
                            <Link to="/stock" aria-label="Stock Page" className="ms-l-20">Stock</Link>
                            <Link to="/suppliers" aria-label="Supplier Page" className="ms-l-20">Supplier</Link>
                            <Link to="/admin_messages" aria-label="Message Page" className='ms-l-20'>Message</Link>
                            <Link to="/admin_review" aria-label="Ratings Page" className="ms-l-20 me-r-20">Ratings</Link>
                            <Button className='admin-btn-login-btn' variant='secondary'>
                                <Link to="/Login" aria-label="About us Page" className='admin-logout-btn'>Log Out</Link>
                            </Button>
                        </nav>
                    </Col>
                </Row>
            </Container>
        </header>
    );
};

export default Header;
