//Patient_Appointment.js
import React, { useState } from 'react';
import './Css/PatientAppointment.css';
import './Css/SignUp.css';
import Header from './Componets/Patientdashboard_Header';
import Footer from './Componets/Footer';
import CommonAppointmentForm from './Componets/AppointmentTable';
import { useAppointments } from './Componets/AppointmentsContext';

const PatientAppointment = () => {
  const { addAppointment } = useAppointments();
  const [formData, setFormData] = useState({
    patientName: '',
    age: '',
    gender: '',
    date: '',
    time: '',
    doctor: '',
    service: ''
  });

  const handleBookAppointment = () => {
    const newAppointment = {
      ...formData,
      id: Date.now() // unique ID based on timestamp
    };
    addAppointment(newAppointment);
    console.log('New appointment added:', newAppointment);
    
    // Clear the form data
    setFormData({
      patientName: '',
      age: '',
      gender: '',
      date: '',
      time: '',
      doctor: '',
      service: ''
    });
  };

  return (
    <div className="patient-appointment-wrapper">
      <Header />
      <div className="patient-appointment-container">
        <div className="appointment-left">
          <div className="app-left">
            <h2 className="page-title">Book an Appointment</h2>
            <CommonAppointmentForm
              formData={formData}
              setFormData={setFormData}
              onSubmit={handleBookAppointment}
              isAdmin={false}
            />
          </div>
        </div>
        <div className="signup-right">
          <div className="signup-right-content text-bg-light opacity-30">
            <h2>Ayurveda and Wellness</h2>
            <p>Ayurveda offers holistic healing...</p>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
};

export default PatientAppointment;

