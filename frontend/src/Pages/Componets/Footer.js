// import React from 'react';
// import '../Css/Footer.css';
// import { Link } from 'react-router-dom';
// import { Container, Row, Col} from 'react-bootstrap';
// import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
// import { faInstagram, faFacebook, faTwitter } from '@fortawesome/free-brands-svg-icons';

// const Footer = () => {
//     return (
//         <footer className="homepage-footer">
//             <Container>
//                 <Row className="text-center text-md-left"> 
//                     <Col md={4} className="mb-3">
//                         <h5>Quick Links</h5>
//                         <ul className="footer-links ">
//                             <li><Link to="/">Home</Link></li>
//                             <li><Link to="/aboutus">About Us</Link></li>
//                             <li><Link to="/services">Services</Link></li>
//                             <li><Link to="/contact">Contact</Link></li>
//                         </ul>
//                     </Col>
//                     <Col md={4} className="mb-3">
//                         <h5>Contact Us</h5>
//                         <p>123 Ayurvedic St, Healing City, 456789</p>
//                         <p>Email: info@ayurvedichospital.com</p>
//                         <p>Phone: +123 456 7890</p>
//                     </Col>
//                     <Col md={4} className="mb-3">
//                         <h5>Follow Us</h5>
//                         <div className="social-icons">
//                             <a href="https://www.facebook.com" aria-label="Facebook">
//                                 <FontAwesomeIcon icon={faFacebook} />
//                             </a>
//                             <a href="https://www.twitter.com" aria-label="Twitter">
//                                 <FontAwesomeIcon icon={faTwitter} />
//                             </a>
//                             <a href="https://www.instagram.com" aria-label="Instagram">
//                                 <FontAwesomeIcon icon={faInstagram} />
//                             </a>
//                         </div>
//                     </Col>
//                 </Row>
//             </Container>
//         </footer>
//     );
// };

// export default Footer;



import React from 'react';
import '../Css/Footer.css';
import { Link } from 'react-router-dom';
import { Container, Row, Col } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faInstagram, faFacebook, faTwitter } from '@fortawesome/free-brands-svg-icons';

const Footer = () => {
    return (
        <footer className="homepage-footer">
            <Container>
                <Row className="text-center text-md-left">
                    <Col md={4} className="mb-3">
                        <h5 style={{color:'white'}}>Quick Links</h5>
                        <ul className="footer-links">
                            <li><Link to="/">Home</Link></li>
                            <li><Link to="/aboutus">About Us</Link></li>
                            <li><Link to="/services">Services</Link></li>
                            <li><Link to="/contact">Contact</Link></li>
                        </ul>
                    </Col>
                    <Col md={4} className="details mb-3" style={{fontSize:'15px',color:'white'}}>
                        <h5>Contact Us</h5>
                        <p>123 Ayurvedic St, Healing City, 456789</p>
                        <p>Email: info@ayurvedichospital.com</p>
                        <p>Phone: +123 456 7890</p>
                    </Col>
                    <Col md={4} className="mb-3">
                        <h5 style={{color:'white'}}>Follow Us</h5>
                        <div className="social-icons">
                            <a href="https://www.facebook.com" aria-label="Facebook">
                                <FontAwesomeIcon icon={faFacebook} />
                            </a>
                            <a href="https://www.twitter.com" aria-label="Twitter">
                                <FontAwesomeIcon icon={faTwitter} />
                            </a>
                            <a href="https://www.instagram.com" aria-label="Instagram">
                                <FontAwesomeIcon icon={faInstagram} />
                            </a>
                        </div>
                    </Col>
                </Row>
            </Container>
        </footer>
    );
};

export default Footer;
