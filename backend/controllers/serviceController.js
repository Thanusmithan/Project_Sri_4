//serviceController.js
const Service = require("../models/Service");

exports.createService = async (req, res) => {
    try {
        const newService = new Service(req.body);
        await newService.save();
        res.status(201).json({ message: "Service created successfully", service: newService });
    } catch (error) {
        res.status(500).json({ message: "Failed to create service", error });
    }
};

exports.getServices = async (req, res) => {
    try {
        const services = await Service.find();
        res.status(200).json(services);
    } catch (error) {
        res.status(500).json({ message: "Failed to retrieve services", error });
    }
};

exports.updateService = async (req, res) => {
    try {
        const { id } = req.params;
        const updatedService = await Service.findByIdAndUpdate(id, req.body, { new: true });
        if (!updatedService) return res.status(404).json({ message: "Service not found" });
        res.status(200).json({ message: "Service updated successfully", service: updatedService });
    } catch (error) {
        res.status(500).json({ message: "Failed to update service", error });
    }
};

exports.deleteService = async (req, res) => {
    try {
        const { id } = req.params;
        await Service.findByIdAndDelete(id);
        res.status(200).json({ message: "Service deleted successfully" });
    } catch (error) {
        res.status(500).json({ message: "Failed to delete service", error });
    }
};
