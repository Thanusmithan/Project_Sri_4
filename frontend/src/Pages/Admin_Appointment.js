//Admin_Appointment.js
import React, { useState } from 'react';
import './Css/Appointment_Admin.css';
import Header from './Componets/Admin_Header';
import Footer from './Componets/Footer';
import { Dropdown } from 'react-bootstrap';
import { FaTrashAlt, FaEllipsisV, FaUser, FaCalendarAlt, FaClock, FaStethoscope, FaConciergeBell, FaEdit } from 'react-icons/fa';
import { useAppointments } from './Componets/AppointmentsContext';

const AdminAppointment = () => {
  const { appointments, deleteAppointment, updateAppointment, convertTo12HourFormat, convertTo24HourFormat, fetchAppointments } = useAppointments();

  const [editAppointmentId, setEditAppointmentId] = useState(null);
  const [formData, setFormData] = useState({
    patientName: '',
    age: '',
    gender: '',
    date: '',
    time: '',
    doctor: '',
    service: '',
  });

  const handleEditAppointment = (appointment) => {
    setEditAppointmentId(appointment._id); // Use _id if that is the identifier in MongoDB
    setFormData({
      ...appointment,
      time: convertTo12HourFormat(appointment.time),
    });
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prevData) => ({ ...prevData, [name]: value }));
  };

  const handleSaveEdit = async () => {
    const updatedAppointment = {
      ...formData,
      _id: editAppointmentId, // Make sure _id is passed if MongoDB uses it as the identifier
      time: convertTo24HourFormat(formData.time),
    };
    await updateAppointment(updatedAppointment); // Await update operation
    await fetchAppointments(); // Refresh the list
    setEditAppointmentId(null); // Close the edit form
  };

  const handleDeleteAppointment = async (id) => {
    await deleteAppointment(id); // Await delete operation
    await fetchAppointments(); // Refresh the list
  };

  // Sort appointments by Date, Time, and then Patient Name in alphabetical order
  const sortedAppointments = [...appointments].sort((a, b) => {
    const dateComparison = new Date(a.date) - new Date(b.date);
    if (dateComparison !== 0) return dateComparison;

    const timeComparison = convertTo24HourFormat(a.time).localeCompare(convertTo24HourFormat(b.time));
    if (timeComparison !== 0) return timeComparison;

    return a.patientName.localeCompare(b.patientName);
  });

  return (
    <div className="admin-appointment-wrapper">
      <Header />
      <div className="container my-5">
        <div className="table-responsive">
          <h2 className="text-center page-title mb-4 pt-3">Manage Patient's Appointments</h2>
          <table className="table table-striped table-hover align-middle">
            <thead className="table-dark">
              <tr>
                <th><FaUser style={{ marginRight: '5px' }} /> Patient Name</th>
                <th><FaUser style={{ marginRight: '5px' }} /> Age</th>
                <th><FaUser style={{ marginRight: '5px' }} /> Gender</th>
                <th><FaCalendarAlt style={{ marginRight: '5px' }} /> Date</th>
                <th><FaClock style={{ marginRight: '5px' }} /> Time</th>
                <th><FaStethoscope style={{ marginRight: '5px' }} /> Doctor</th>
                <th><FaConciergeBell style={{ marginRight: '5px' }} /> Service</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sortedAppointments.map((appointment) => (
                <tr key={appointment._id}>
                  <td>{appointment.patientName}</td>
                  <td>{appointment.age}</td>
                  <td>{appointment.gender}</td>
                  <td>{appointment.date}</td>
                  <td>{convertTo12HourFormat(appointment.time)}</td>
                  <td>{appointment.doctor}</td>
                  <td>{appointment.service}</td>
                  <td>
                    <Dropdown>
                      <Dropdown.Toggle variant="secondary" id={`dropdownMenuButton-${appointment._id}`}>
                        <FaEllipsisV />
                      </Dropdown.Toggle>
                      <Dropdown.Menu>
                        <Dropdown.Item as="button" onClick={() => handleEditAppointment(appointment)}>
                          <FaEdit className="me-2" /> Edit
                        </Dropdown.Item>
                        <Dropdown.Item as="button" onClick={() => handleDeleteAppointment(appointment._id)}>
                          <FaTrashAlt className="me-2" /> Delete
                        </Dropdown.Item>
                      </Dropdown.Menu>
                    </Dropdown>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Edit Appointment Modal */}
        {editAppointmentId && (
          <div className="modal show" style={{ display: 'block' }}>
            <div className="modal-dialog">
              <div className="modal-content">
                <div className="modal-header">
                  <h5 className="modal-title">Edit Appointment</h5>
                  <button
                    type="button"
                    className="btn-close"
                    onClick={() => setEditAppointmentId(null)}
                    aria-label="Close"
                  ></button>
                </div>
                <div className="modal-body">
                  <form>
                    <div className="mb-3">
                      <label>Patient Name</label>
                      <input
                        type="text"
                        name="patientName"
                        value={formData.patientName}
                        onChange={handleChange}
                        className="form-control"
                        required
                      />
                    </div>
                    <div className="mb-3">
                      <label>Age</label>
                      <input
                        type="number"
                        name="age"
                        value={formData.age}
                        onChange={handleChange}
                        className="form-control"
                        required
                      />
                    </div>
                    <div className="mb-3">
                      <label>Gender</label>
                      <select
                        name="gender"
                        value={formData.gender}
                        onChange={handleChange}
                        className="form-control"
                        required
                      >
                        <option value="Male">Male</option>
                        <option value="Female">Female</option>
                      </select>
                    </div>
                    <div className="mb-3">
                      <label>Date</label>
                      <input
                        type="date"
                        name="date"
                        value={formData.date}
                        onChange={handleChange}
                        className="form-control"
                        required
                      />
                    </div>
                    <div className="mb-3">
                      <label>Time</label>
                      <input
                        type="time"
                        name="time"
                        value={formData.time}
                        onChange={handleChange}
                        className="form-control"
                        required
                      />
                    </div>
                    <div className="mb-3">
                      <label>Doctor</label>
                      <input
                        type="text"
                        name="doctor"
                        value={formData.doctor}
                        onChange={handleChange}
                        className="form-control"
                        required
                      />
                    </div>
                    <div className="mb-3">
                      <label>Service</label>
                      <input
                        type="text"
                        name="service"
                        value={formData.service}
                        onChange={handleChange}
                        className="form-control"
                        required
                      />
                    </div>
                    <button type="button" className="btn btn-primary" onClick={handleSaveEdit}>
                      Save Changes
                    </button>
                  </form>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
      <Footer />
    </div>
  );
};

export default AdminAppointment;
