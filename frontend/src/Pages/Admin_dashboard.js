// AdminDashboard.js
import React from 'react';
import './Css/Admin_dashboard.css';
import Header from './Componets/Admin_Header';
import Footer from './Componets/Footer';
import { Container, Row, Col, Card, Button } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCalendarAlt, faConciergeBell, faEnvelope, faBoxes, faTruck, faStar } from '@fortawesome/free-solid-svg-icons';

const AdminDashboard = () => {
  return (
    <div className="admin-dashboard">
      {/* Header */}
      <Header />

      {/* Welcome Section */}
      <section className="admin-welcome-section">
        <div className="admin-overlay">
          <div className="admin-welcome-content">
            <h1>Welcome to the Admin Dashboard</h1>
            <p>Manage hospital appointments, services and communicate with patients effectively.</p>
            <Button href="/admin_appointment" className="admin-welcome-btn me-3">Manage Appointments</Button>
            <Button href="/admin_patient_details" className="admin-welcome-btn">View Patients Details</Button>
          </div>
        </div>
      </section>

      {/* Dashboard Content */}
      {/* <Container className="admin-dashboard-content">
        <h2 className="admin-section-title">Dashboard Overview</h2>
        <Row>
          <Col md={4}>
            <Card className="admin-dashboard-card">
              <Card.Body>
                <Card.Title>Appointments</Card.Title>
                <Card.Text>View and manage all upcoming patient appointments.</Card.Text>
                <Button href="/admin_appointment" className="admin-dashboard-btn">Manage Appointments</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="admin-dashboard-card">
              <Card.Body>
                <Card.Title>Services</Card.Title>
                <Card.Text>Update and add new services available in the hospital.</Card.Text>
                <Button href="/admin_services" className="admin-dashboard-btn">Manage Services</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="admin-dashboard-card">
              <Card.Body>
                <Card.Title>Messages</Card.Title>
                <Card.Text>Communicate with patients and staff through secure messaging.</Card.Text>
                <Button href="/admin_messages" className="admin-dashboard-btn">View Messages</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="admin-dashboard-card">
              <Card.Body>
                <Card.Title>Stock Management</Card.Title>
                <Card.Text>Monitor and update medical supplies and inventory levels.</Card.Text>
                <Button href="/stock" className="admin-dashboard-btn">Manage Stock</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="admin-dashboard-card">
              <Card.Body>
                <Card.Title>Supplier Information</Card.Title>
                <Card.Text>View and manage supplier details and orders.</Card.Text>
                <Button href="/suppliers" className="admin-dashboard-btn">Manage Suppliers</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="admin-dashboard-card">
              <Card.Body>
                <Card.Title>Ratings & Reviews</Card.Title>
                <Card.Text>Check patient feedback and respond to reviews.</Card.Text>
                <Button href="/admin_review" className="admin-dashboard-btn">View Reviews</Button>
              </Card.Body>
            </Card>
          </Col>
        </Row>
      </Container> */}
      <Container className="admin-dashboard-content">
        <h2 className="admin-section-title">Dashboard Overview</h2>
        <Row>
          <Col md={4}>
            <Card className="admin-dashboard-card">
              <Card.Body>
                <div className='d-flex justify-content-start align-items-baseline'>
                  <FontAwesomeIcon icon={faCalendarAlt} className="admin-card-icon me-2" />
                  <Card.Title>Appointments</Card.Title>
                </div>
                <Card.Text>View and manage all upcoming patient appointments.</Card.Text>
                <Button href="/admin_appointment" className="admin-dashboard-btn">Manage Appointments</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="admin-dashboard-card">
              <Card.Body>
                <div className='d-flex justify-content-start align-items-baseline'>
                  <FontAwesomeIcon icon={faConciergeBell} className="admin-card-icon me-2" />
                  <Card.Title>Services</Card.Title>
                </div>
                <Card.Text>Update and add new services available in the hospital.</Card.Text>
                <Button href="/admin_services" className="admin-dashboard-btn">Manage Services</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="admin-dashboard-card">
              <Card.Body>
                <div className='d-flex justify-content-start align-items-baseline'>
                  <FontAwesomeIcon icon={faEnvelope} className="admin-card-icon me-2" />
                  <Card.Title>Messages</Card.Title>
                </div>
                <Card.Text>Communicate with patients and staff through secure messaging.</Card.Text>
                <Button href="/admin_messages" className="admin-dashboard-btn">View Messages</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="admin-dashboard-card">
              <Card.Body>
                <div className='d-flex justify-content-start align-items-baseline'>
                  <FontAwesomeIcon icon={faBoxes} className="admin-card-icon me-2" />
                  <Card.Title>Stock Management</Card.Title>
                </div>
                <Card.Text>Monitor and update medical supplies and inventory levels.</Card.Text>
                <Button href="/stock" className="admin-dashboard-btn">Manage Stock</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="admin-dashboard-card">
              <Card.Body>
                <div className='d-flex justify-content-start align-items-baseline'>
                  <FontAwesomeIcon icon={faTruck} className="admin-card-icon me-2" />
                  <Card.Title>Supplier Information</Card.Title>
                </div>
                <Card.Text>View and manage supplier details and orders.</Card.Text>
                <Button href="/suppliers" className="admin-dashboard-btn">Manage Suppliers</Button>
              </Card.Body>
            </Card>
          </Col>
          <Col md={4}>
            <Card className="admin-dashboard-card">
              <Card.Body>
                <div className='d-flex justify-content-start align-items-baseline'>
                  <FontAwesomeIcon icon={faStar} className="admin-card-icon me-2" />
                  <Card.Title>Ratings & Reviews</Card.Title>
                </div>
                <Card.Text>Check patient feedback and respond to reviews.</Card.Text>
                <Button href="/admin_review" className="admin-dashboard-btn">View Reviews</Button>
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

export default AdminDashboard;
