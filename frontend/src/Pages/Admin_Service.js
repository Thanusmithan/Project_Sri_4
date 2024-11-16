// Admin_Service.js
import React, { useState, useEffect } from 'react';
import './Css/Admin_Services.css';
import { useServices } from './Componets/ServicesContext'; // Import useServices hook
import Header from './Componets/Admin_Header';
import Footer from './Componets/Footer';
import Card from 'react-bootstrap/Card';
import Dropdown from 'react-bootstrap/Dropdown';
import Alert from 'react-bootstrap/Alert';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { FaEdit, FaTrash } from "react-icons/fa";
// import { faClipboardList, faUserMd, faPlusCircle } from '@fortawesome/free-solid-svg-icons';
import {faPlusCircle } from '@fortawesome/free-solid-svg-icons';


const Admin_Service = () => {
  const [serviceName, setServiceName] = useState('');
  const [serviceDescription, setServiceDescription] = useState('');
  const [doctorName, setDoctorName] = useState('');
  const [editingServiceId, setEditingServiceId] = useState(null);
  const [showAlert, setShowAlert] = useState(false);
  const [showSuccessAlert, setShowSuccessAlert] = useState(false);
  const { services, addService, editService, deleteService } = useServices(); // Use useServices hook

  useEffect(() => {
    if (showSuccessAlert) {
      const timer = setTimeout(() => {
        setShowSuccessAlert(false);
      }, 2000);
      return () => clearTimeout(timer);
    }
  }, [showSuccessAlert]);

  const handleAddOrEditService = () => {
    if (!serviceName || !serviceDescription || !doctorName) {
      setShowAlert(true);
      setTimeout(() => setShowAlert(false), 2000);
      return;
    }

    if (editingServiceId) {
      editService(editingServiceId, { serviceName, serviceDescription, doctorName });
      setEditingServiceId(null);
    } else {
      addService({ serviceName, serviceDescription, doctorName });
    }

    setShowSuccessAlert(true);
    setTimeout(() => setShowSuccessAlert(false), 2000);

    setServiceName('');
    setServiceDescription('');
    setDoctorName('');
  };

  const handleEditService = (service) => {
    setServiceName(service.serviceName);
    setServiceDescription(service.serviceDescription);
    setDoctorName(service.doctorName);
    setEditingServiceId(service._id);
  };

  return (
    <>
      <Header />
      <div className="page-wrapper">
        <div className="container">
          {showAlert && (
            <Alert variant="danger" onClose={() => setShowAlert(false)} dismissible>
              <strong>Please fill in all fields before submitting!</strong>
            </Alert>
          )}
          {showSuccessAlert && (
            <Alert variant="success" onClose={() => setShowSuccessAlert(false)} dismissible>
              <strong>Service added successfully!</strong>
            </Alert>
          )}
          <div className="service-form-container">
            <h2 className="page-title text-center mb-4">Manage Hospital Services</h2>
            <form className="service-form">
              <div className="mb-3">
                <label>Service Name:</label>
                <input
                  type="text"
                  className="form-control"
                  value={serviceName}
                  onChange={(e) => setServiceName(e.target.value)}
                />
              </div>
              <div className="mb-3">
                <label>Service Description:</label>
                <textarea
                  className="form-control"
                  value={serviceDescription}
                  onChange={(e) => setServiceDescription(e.target.value)}
                />
              </div>
              <div className="mb-3">
                <label>Doctor's Name:</label>
                <input
                  type="text"
                  className="form-control"
                  value={doctorName}
                  onChange={(e) => setDoctorName(e.target.value)}
                />
              </div>
              <button type="button" onClick={handleAddOrEditService} className="btn btn-service-primary">
                <FontAwesomeIcon icon={faPlusCircle} className="me-2" />
                {editingServiceId ? 'Update Service' : 'Add Service'}
              </button>
            </form>
          </div>
          <h3 className="mt-4">Existing Services</h3>
          <div className="row mt-3">
            {services.map((service) => (
              <div className="col-md-4 mb-4" key={service._id}>
                <Card className="service-card shadow h-100">
                  <Card.Header>{service.serviceName}</Card.Header>
                  <Card.Body>
                    <p>{service.serviceDescription}</p>
                    <footer>{service.doctorName}</footer>
                  </Card.Body>
                  <Card.Footer>
                    <Dropdown className="w-100">
                      <Dropdown.Toggle variant="success" id={`dropdownMenuButton-${service._id}`}>
                        Manage
                      </Dropdown.Toggle>
                      <Dropdown.Menu>
                        <Dropdown.Item onClick={() => handleEditService(service)}>
                          <FaEdit /> Edit
                        </Dropdown.Item>
                        <Dropdown.Item onClick={() => deleteService(service._id)}>
                          <FaTrash /> Delete
                        </Dropdown.Item>
                      </Dropdown.Menu>
                    </Dropdown>
                  </Card.Footer>
                </Card>
              </div>
            ))}
          </div>
        </div>
      </div>
      <Footer />
    </>
  );
};

export default Admin_Service;

