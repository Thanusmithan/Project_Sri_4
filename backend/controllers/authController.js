// authController.js
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

exports.register = async (req, res) => {
    try {
        const { firstName, lastName, email, phone, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ 
            firstName, 
            lastName, 
            email, 
            phone, 
            password: hashedPassword 
        });
        await user.save();

        res.status(201).json({ 
            message: "User registered successfully", 
            user: { 
                firstName: user.firstName, 
                lastName: user.lastName, 
                email: user.email, 
                phone: user.phone 
            }
        });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ message: "Server error" });
    }
};

exports.login = async (req, res) => {
    try {
        const { email, password, isAdmin } = req.body;
        const user = await User.findOne({ email });

        if (!user) return res.status(400).json({ message: "Invalid credentials" });

        // Enforce admin credentials restriction
        if (isAdmin) {
            if (email !== "admin@hospital.com" || password !== "admin123") {
                return res.status(403).json({ message: "Unauthorized access to admin role" });
            }
        } else {
            // Prevent admin credentials from being used as patient credentials
            if (email === "admin@hospital.com") {
                return res.status(403).json({ message: "Admin credentials cannot be used for patient login" });
            }
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });

        res.json({
            token,
            user: {
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                phone: user.phone,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Server error" });
    }
};

exports.updateUser = async (req, res) => {
    try {
        const { firstName, lastName, email, phone } = req.body;
        const userId = req.user.id;

        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { firstName, lastName, email, phone },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({
            message: "User updated successfully",
            user: {
                firstName: updatedUser.firstName,
                lastName: updatedUser.lastName,
                email: updatedUser.email,
                phone: updatedUser.phone,
                role: updatedUser.role
            }
        });
    } catch (error) {
        console.error("Update error:", error);
        res.status(500).json({ message: "Server error" });
    }
};
