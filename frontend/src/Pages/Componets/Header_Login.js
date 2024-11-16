import React from 'react';
import '../Css/Header_Login.css';
import logo from '../Images/logo.svg';
import { Link } from 'react-router-dom';
import { Container, Row, Col, Button } from 'react-bootstrap';

const Header = () => {
    return (
        <header className="homepage-header">
            <Container>
                <Row className="d-flex justify-content-center">
                    <Col md={3}>
                        <div className="login-logo">
                            <img src={logo} alt="Ayurvedic Medical Hospital" />
                        </div>
                    </Col>
                    <Col md={9}>
                        <nav className="login-nav-links">
                            <Link to="/" aria-label="Home Page" className='ms-l-20'>Home</Link>
                            <Link to="/aboutus" aria-label="About Us Page" className='ms-l-20'>About Us</Link>
                            <Link to="/services" aria-label="Services Page" className='ms-l-20'>Services</Link>
                            <Link to="/contact" aria-label="Contact Page" className='ms-l-20 me-l-20'>Contact</Link>
                            <Button className='btn-login-btn' variant='secondary'>
                                <Link to="/Login" aria-label="About us Page" className='login-nav-btn'>Log In</Link>
                            </Button>
                        </nav>
                    </Col>
                </Row>
            </Container>
        </header>
    );
};

export default Header;
