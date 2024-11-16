// backend/models/Service.js
const mongoose = require("mongoose");

const serviceSchema = new mongoose.Schema({
    serviceName: { type: String, required: true },
    serviceDescription: { type: String, required: true },
    doctorName: { type: String, required: true },
});

module.exports = mongoose.model("Service", serviceSchema);
