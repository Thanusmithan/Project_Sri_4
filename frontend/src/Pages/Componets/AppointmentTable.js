// CommonAppointmentForm.js
// 

// CommonAppointmentForm.js
import React from 'react';
import '../Css/PatientAppointment.css';

const CommonAppointmentForm = ({ formData, setFormData, onSubmit, isAdmin }) => {
  return (
    <form className="appointment-form">
      <div className="row g-3">
        <div className="col-md-12">
          <div className="mb-3">
            <label className="form-label" htmlFor="patientName">Patient Name:</label>
            <input
              type="text"
              id="patientName"
              name="patientName"
              className="form-control"
              placeholder="Enter your name"
              value={formData.patientName}
              onChange={(e) => setFormData({ ...formData, patientName: e.target.value })}
            />
          </div>
        </div>
        
        <div className="col-md-12">
          <div className="mb-3">
            <label className="form-label" htmlFor="age">Age:</label>
            <input
              type="number"
              id="age"
              name="age"
              className="form-control"
              placeholder="Enter your age"
              value={formData.age}
              onChange={(e) => setFormData({ ...formData, age: e.target.value })}
            />
          </div>
        </div>

        <div className="col-md-12">
          <div className="mb-3">
            <label className="form-label" htmlFor="gender">Gender:</label>
            <select
              id="gender"
              name="gender"
              className="form-select"
              value={formData.gender}
              onChange={(e) => setFormData({ ...formData, gender: e.target.value })}
            >
              <option value="" disabled>Select gender</option>
              <option value="Male">Male</option>
              <option value="Female">Female</option>
              <option value="Other">Other</option>
            </select>
          </div>
        </div>

        <div className="col-md-12">
          <div className="mb-3">
            <label className="form-label" htmlFor="date">Date:</label>
            <input
              type="date"
              id="date"
              name="date"
              className="form-control"
              value={formData.date}
              onChange={(e) => setFormData({ ...formData, date: e.target.value })}
            />
          </div>
        </div>

        <div className="col-md-12">
          <div className="mb-3">
            <label className="form-label" htmlFor="time">Time:</label>
            <input
              type="time"
              id="time"
              name="time"
              className="form-control"
              value={formData.time}
              onChange={(e) => setFormData({ ...formData, time: e.target.value })}
            />
          </div>
        </div>

        <div className="col-md-12">
          <div className="mb-3">
            <label className="form-label" htmlFor="doctor">Select a Doctor:</label>
            <select
              id="doctor"
              name="doctor"
              className="form-select"
              value={formData.doctor}
              onChange={(e) => setFormData({ ...formData, doctor: e.target.value })}
            >
              <option value="" disabled>Select a doctor</option>
              <option value="Dr. Smith">Dr. Smith</option>
              <option value="Dr. John">Dr. John</option>
            </select>
          </div>
        </div>

        <div className="col-md-12">
          <div className="mb-3">
            <label className="form-label" htmlFor="service">Service:</label>
            <select
              id="service"
              name="service"
              className="form-select"
              value={formData.service}
              onChange={(e) => setFormData({ ...formData, service: e.target.value })}
            >
              <option value="" disabled>Select a service</option>
              <option value="Panchakarma Therapy">Panchakarma Therapy</option>
              <option value="Abhyanga Massage">Abhyanga Massage</option>
            </select>
          </div>
        </div>

        {!isAdmin ? (
          <div className="col-12 text-center">
            <button type="button" className="btn-patient-appointment btn-success" onClick={onSubmit}>
              Book Appointment
            </button>
          </div>
        ) : (
          <div className="col-12 text-center">
            <button type="button" className="btn btn-info" onClick={onSubmit}>
              Save Changes
            </button>
          </div>
        )}
      </div>
    </form>
  );
};

export default CommonAppointmentForm;
