// models/Appointment.js
const mongoose = require("mongoose");

const appointmentSchema = new mongoose.Schema({
    patientName: { type: String, required: true },
    age: { type: Number, required: true },
    gender: { type: String, required: true },
    date: { type: String, required: true },
    time: { type: String, required: true },
    doctor: { type: String, required: true },
    service: { type: String, required: true },
});

module.exports = mongoose.model("Appointment", appointmentSchema);

