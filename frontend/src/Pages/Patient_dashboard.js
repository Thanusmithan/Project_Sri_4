//patient_Dashboard.js
import React from 'react';
import Header from './Componets/Patientdashboard_Header';
import './Css/Patient_dashboard.css';
import Footer from './Componets/Footer';
import { Container, Row, Col, Card, Button } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCalendarAlt, faFileMedical, faComments, faConciergeBell, faStar } from '@fortawesome/free-solid-svg-icons';

const PatientDashboard = () => {
  return (
    <div className="patient-dashboard">
      {/* Header */}
      <Header />

      {/* Welcome Section */}
      <section className="patient-welcome-section">
        <div className="patient-overlay">
          <div className="patient-welcome-content">
            <h1>Welcome to User Dashboard</h1>
            <p>Manage your appointments, explore our services and communicate with our team.</p>
            <Button href="/patient_appointment" className="patient-welcome-btn">View Appointments</Button>
          </div>
        </div>
      </section>
      <Container className="patient-dashboard-content">
        <h2 className="patient-section-title">Dashboard Overview</h2>
        <Row>
          <Col md={4}>
            <Card className="patient-dashboard-card">
              <Card.Body>
                <div className='d-flex justify-content-start align-items-baseline'>
                  <FontAwesomeIcon icon={faCalendarAlt} className="card-icon me-2" />
                  <Card.Title>Appointments</Card.Title>
                </div>
                <Card.Text>View, schedule, or cancel your appointments.</Card.Text>
                <Button href="/patient_appointment" className="patient-dashboard-btn">Manage Appointments</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="patient-dashboard-card">
              <Card.Body>
                <div className='d-flex justify-content-start align-items-baseline'>
                  <FontAwesomeIcon icon={faFileMedical} className="card-icon me-2" />
                  <Card.Title>Health Records</Card.Title>
                </div>
                <Card.Text>Access and review your health records securely.</Card.Text>
                <Button href="/health-records" className="patient-dashboard-btn">View Records</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="patient-dashboard-card">
              <Card.Body>
                <div className='d-flex justify-content-start align-items-baseline'>
                  <FontAwesomeIcon icon={faComments} className="card-icon me-2" />
                  <Card.Title>Messages</Card.Title>
                </div>
                <Card.Text>Communicate directly with your healthcare providers.</Card.Text>
                <Button href="/patient_messages" className="patient-dashboard-btn">View Messages</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="patient-dashboard-card">
              <Card.Body>
                <div className='d-flex justify-content-start align-items-baseline'>
                  <FontAwesomeIcon icon={faConciergeBell} className="card-icon me-2" />
                  <Card.Title>Services</Card.Title>
                </div>
                <Card.Text>Discover a range of Ayurvedic services and treatments.</Card.Text>
                <Button href="/patient_services" className="patient-dashboard-btn">Explore Services</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="patient-dashboard-card">
              <Card.Body>
                <div className='d-flex justify-content-start align-items-baseline'>
                  <FontAwesomeIcon icon={faStar} className="card-icon me-2" />
                  <Card.Title>Ratings & Reviews</Card.Title>
                </div>
                <Card.Text>Share feedback on your experience with our services.</Card.Text>
                <Button href="/patient_review" className="patient-dashboard-btn">Submit a Review</Button>
              </Card.Body>
            </Card>
          </Col>
        </Row>
      </Container>
      {/* Footer */}
      <Footer />
    </div>
  );
};

export default PatientDashboard;


