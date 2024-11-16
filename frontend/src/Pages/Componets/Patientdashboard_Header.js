// import React from 'react';
// import '../Css/Parient_dashboard_Header.css';
// import logo from '../Images/logo.svg';
// import { Link } from 'react-router-dom';
// import { Container, Row, Col, Button,Dropdown} from 'react-bootstrap';

// const Header = () => {
//     return (
//         <header className="homepage-header">
//             <Container>
//                 <Row className="d-flex justify-content-center">
//                     <Col md={3}>
//                         <div className="logo">
//                             <img src={logo} alt="Ayurvedic Medical Hospital" />
//                         </div>
//                     </Col>
//                     <Col md={9}>
//                         <nav className="nav-links">
//                             <Link to="/patient_dashboard" aria-label="Home Page" className='ms-l-20'>Dashboard</Link>
//                             <Link to="/patient_appointment" aria-label="Services Page" className='ms-l-20'>Appointments</Link>
//                             <Link to="/patient_services" aria-label="Services Page" className='ms-l-20'>Services</Link>
//                             <Link to="/patient_messages" aria-label="Services Page" className='ms-l-20'>Messages</Link>
//                             <Link to="/patient_review" aria-label="Services Page" className='ms-l-20 me-r-20'>Ratings</Link>
//                             {/* <Button variant='secondary' className='patient-logout-btn'>
//                                 <Link to="/Login" aria-label="About us Page" className=''>Log Out</Link>
//                             </Button> */}
//                         </nav>
//                     </Col>
//                 </Row>
//             </Container>
//         </header>
//     );
// };

// export default Header;


//UserDashboard header.js code --  Before Backend integration
//UserDashboard header.js code
// import React, { useEffect, useState } from 'react';
// import '../Css/Parient_dashboard_Header.css';
// import logo from '../Images/logo.svg';
// import { Link } from 'react-router-dom';
// import { Container, Row, Col, Button, Dropdown } from 'react-bootstrap';
// import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
// import { faUserCircle, faHome, faCalendarAlt, faConciergeBell, faEnvelope, faStar, faSignOutAlt } from '@fortawesome/free-solid-svg-icons';

// const Header = () => {
//     const [user, setUser] = useState({ name: '', email: '' });

//     useEffect(() => {
//         const storedUser = JSON.parse(localStorage.getItem('user')) || { name: 'John Doe', email: 'john.doe@example.com' };
//         setUser(storedUser);
//     }, []);

//     return (
//         <header className="homepage-header">
//             <Container>
//                 <Row className="d-flex align-items-center justify-content-between">
//                     <Col md={9}>
//                         <div className="logo">
//                             <img src={logo} alt="Ayurvedic Medical Hospital" />
//                         </div>
//                     </Col>
//                     {/* <Col md={6}>
//                         <nav className="nav-links">
//                             <Link to="/patient_dashboard" className="ms-l-20">Dashboard</Link>
//                             <Link to="/patient_appointment" className="ms-l-20">Appointments</Link>
//                             <Link to="/patient_services" className="ms-l-20">Services</Link>
//                             <Link to="/patient_messages" className="ms-l-20">Messages</Link>
//                             <Link to="/patient_review" className="ms-l-20 me-r-20">Ratings</Link>
//                         </nav> 
//                     </Col> */}
//                     <Col md={3} className="text-end">
//                         <div className="user-info">
//                             <FontAwesomeIcon icon={faUserCircle} className="user-icon" />
//                             <span className="user-name">Hello, {user.name}</span>
//                             <Dropdown>
//                                 <Dropdown.Toggle  variant='secondary'  className="patient-profile-dropdown-toggle">
//                                 </Dropdown.Toggle>
//                                 <Dropdown.Menu>
//                                     <Dropdown.Item href="/profile">
//                                         <FontAwesomeIcon icon={faUserCircle} className="dropdown-icon me-2"  /> View Profile
//                                     </Dropdown.Item>
//                                     <Dropdown.Divider />
//                                     <Dropdown.Item href="/patient_dashboard">
//                                         <FontAwesomeIcon icon={faHome} className="dropdown-icon me-2" /> Home
//                                     </Dropdown.Item>
//                                     <Dropdown.Item href="/patient_appointment">
//                                         <FontAwesomeIcon icon={faCalendarAlt} className="dropdown-icon me-2" /> Appointment
//                                     </Dropdown.Item>
//                                     <Dropdown.Item href="/patient_services">
//                                         <FontAwesomeIcon icon={faConciergeBell} className="dropdown-icon me-2" /> Service
//                                     </Dropdown.Item>
//                                     <Dropdown.Item href="/patient_messages">
//                                         <FontAwesomeIcon icon={faEnvelope} className="dropdown-icon me-2" /> Messages
//                                     </Dropdown.Item>
//                                     <Dropdown.Item href="/patient_review">
//                                         <FontAwesomeIcon icon={faStar} className="dropdown-icon me-2" /> Ratings
//                                     </Dropdown.Item>
//                                     <Dropdown.Divider />
//                                     <Dropdown.Item as={Link} to="/Login" className="text-white">
//                                         <FontAwesomeIcon icon={faSignOutAlt} className="dropdown-icon me-2" /> Log Out
//                                     </Dropdown.Item>
//                                 </Dropdown.Menu>
//                             </Dropdown>
//                         </div>
//                     </Col>
//                 </Row>
//             </Container>
//         </header>
//     );
// };

// export default Header;


//UserDashboard header.js code --  After Backend integration
//UserDashboard header.js code
// import React, { useEffect, useState } from 'react';
// import '../Css/Parient_dashboard_Header.css';
// import logo from '../Images/logo.svg';
// import { Link } from 'react-router-dom';
// import { Container, Row, Col, Dropdown } from 'react-bootstrap';
// import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
// import { faUserCircle, faHome, faCalendarAlt, faConciergeBell, faEnvelope, faStar, faSignOutAlt } from '@fortawesome/free-solid-svg-icons';

// const Header = () => {
//     const [user, setUser] = useState({ firstName: '', lastName: '', email: '' });

//     useEffect(() => {
//         const storedUser = JSON.parse(localStorage.getItem('user')) || { firstName: 'John', lastName: 'Doe', email: 'john.doe@example.com' };
//         setUser(storedUser);
//     }, []);

//     return (
//         <header className="homepage-header">
//             <Container>
//                 <Row className="d-flex align-items-center justify-content-between">
//                     <Col md={9}>
//                         <div className="logo">
//                             <img src={logo} alt="Ayurvedic Medical Hospital" />
//                         </div>
//                     </Col>
//                     <Col md={3} className="text-end">
//                         <div className="user-info">
//                             <FontAwesomeIcon icon={faUserCircle} className="user-icon" />
//                             <span className="user-name">Hello, {user.firstName} {user.lastName}</span>
//                             <Dropdown>
//                                 <Dropdown.Toggle variant='secondary' className="patient-profile-dropdown-toggle">
//                                 </Dropdown.Toggle>
//                                 <Dropdown.Menu>
//                                     <Dropdown.Item href="/profile">
//                                         <FontAwesomeIcon icon={faUserCircle} className="dropdown-icon me-2" /> View Profile
//                                     </Dropdown.Item>
//                                     <Dropdown.Divider />
//                                     <Dropdown.Item href="/patient_dashboard">
//                                         <FontAwesomeIcon icon={faHome} className="dropdown-icon me-2" /> Home
//                                     </Dropdown.Item>
//                                     <Dropdown.Item href="/patient_appointment">
//                                         <FontAwesomeIcon icon={faCalendarAlt} className="dropdown-icon me-2" /> Appointment
//                                     </Dropdown.Item>
//                                     <Dropdown.Item href="/patient_services">
//                                         <FontAwesomeIcon icon={faConciergeBell} className="dropdown-icon me-2" /> Service
//                                     </Dropdown.Item>
//                                     <Dropdown.Item href="/patient_messages">
//                                         <FontAwesomeIcon icon={faEnvelope} className="dropdown-icon me-2" /> Messages
//                                     </Dropdown.Item>
//                                     <Dropdown.Item href="/patient_review">
//                                         <FontAwesomeIcon icon={faStar} className="dropdown-icon me-2" /> Ratings
//                                     </Dropdown.Item>
//                                     <Dropdown.Divider />
//                                     <Dropdown.Item as={Link} to="/Login" className="text-white">
//                                         <FontAwesomeIcon icon={faSignOutAlt} className="dropdown-icon me-2" /> Log Out
//                                     </Dropdown.Item>
//                                 </Dropdown.Menu>
//                             </Dropdown>
//                         </div>
//                     </Col>
//                 </Row>
//             </Container>
//         </header>
//     );
// };

// export default Header;


// 14.11.2024
//UserDashboard header.js code
import React, { useEffect, useState } from 'react';
import '../Css/Parient_dashboard_Header.css';
import logo from '../Images/logo.svg';
import { Link } from 'react-router-dom';
import { Container, Row, Col, Dropdown } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faUserCircle, faHome, faCalendarAlt, faConciergeBell, faEnvelope, faStar, faSignOutAlt } from '@fortawesome/free-solid-svg-icons';

const Header = () => {
    const [user, setUser] = useState({ firstName: '', lastName: '', email: '' });

    useEffect(() => {
        const storedUser = JSON.parse(localStorage.getItem('user')) || { firstName: 'John', lastName: 'Doe', email: 'john.doe@example.com' };
        setUser(storedUser);
    }, []);

    return (
        <header className="homepage-header">
            <Container>
                <Row className="d-flex align-items-center justify-content-between">
                    <Col lg={9} md={9}>
                        <div className="logo">
                            <img src={logo} alt="Ayurvedic Medical Hospital" />
                        </div>
                    </Col>
                    <Col className="text-end" lg={3} md={3}>
                        <div className="user-info">
                            <FontAwesomeIcon icon={faUserCircle} className="user-icon" />
                            <span className="user-name">Hello!, {user.lastName}</span>
                            <Dropdown>
                                <Dropdown.Toggle variant="secondary" className="patient-profile-dropdown-toggle" />
                                <Dropdown.Menu className="dropdown-menu-custom">
                                    <Dropdown.Item href="/profile">
                                        <FontAwesomeIcon icon={faUserCircle} className="dropdown-icon me-2" /> View Profile
                                    </Dropdown.Item>
                                    <Dropdown.Divider />
                                    <Dropdown.Item href="/patient_dashboard">
                                        <FontAwesomeIcon icon={faHome} className="dropdown-icon me-2" /> Home
                                    </Dropdown.Item>
                                    <Dropdown.Item href="/patient_appointment">
                                        <FontAwesomeIcon icon={faCalendarAlt} className="dropdown-icon me-2" /> Appointment
                                    </Dropdown.Item>
                                    <Dropdown.Item href="/patient_services">
                                        <FontAwesomeIcon icon={faConciergeBell} className="dropdown-icon me-2" /> Service
                                    </Dropdown.Item>
                                    <Dropdown.Item href="/patient_messages">
                                        <FontAwesomeIcon icon={faEnvelope} className="dropdown-icon me-2" /> Messages
                                    </Dropdown.Item>
                                    <Dropdown.Item href="/patient_review">
                                        <FontAwesomeIcon icon={faStar} className="dropdown-icon me-2" /> Ratings
                                    </Dropdown.Item>
                                    <Dropdown.Divider />
                                    <Dropdown.Item as={Link} to="/Login" className="text-white">
                                        <FontAwesomeIcon icon={faSignOutAlt} className="dropdown-icon me-2" /> Log Out
                                    </Dropdown.Item>
                                </Dropdown.Menu>
                            </Dropdown>
                        </div>
                    </Col>
                </Row>
            </Container>
        </header>
    );
};

export default Header;
