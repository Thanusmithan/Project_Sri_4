// routes/userRoutes.js - for Patients Details Page
const express = require("express");
const router = express.Router();
const User = require("../models/User");

// GET all users
router.get("/", async (req, res) => {
    try {
        const users = await User.find(); // Fetch all users
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: "Error fetching users", error });
    }
});

// PUT update a user
router.put("/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const updatedUser = await User.findByIdAndUpdate(id, req.body, { new: true });
        res.status(200).json(updatedUser);
    } catch (error) {
        res.status(500).json({ message: "Error updating user", error });
    }
});

// DELETE a user
router.delete("/:id", async (req, res) => {
    try {
        const { id } = req.params;
        await User.findByIdAndDelete(id);
        res.status(200).json({ message: "User deleted successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error deleting user", error });
    }
});

module.exports = router;
