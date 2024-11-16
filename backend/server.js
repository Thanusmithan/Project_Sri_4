// server.js
const express = require("express");
const dotenv = require("dotenv");
const connectDB = require("./config/db"); // Database connection file
const authRoutes = require("./routes/authRoutes");
const appointmentRoutes = require("./routes/appointmentRoutes"); // Appointment routes
const serviceRoutes = require("./routes/serviceRoutes"); // Service routes
const userRoutes = require("./routes/userRoutes"); // User routes
const cors = require("cors");
const User = require("./models/User");
const bcrypt = require("bcryptjs");

dotenv.config(); // Load environment variables

const app = express();

// Connect to MongoDB
connectDB();

// Middleware
app.use(cors()); // Enable CORS
app.use(express.json()); // Parse JSON request bodies

// Seed the admin user if it doesn't exist
const seedAdminUser = async () => {
    try {
        const existingAdmin = await User.findOne({ email: "admin@hospital.com" });
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash("admin123", 10);
            const admin = new User({
                firstName: "Admin",
                lastName: "User",
                email: "admin@hospital.com",
                phone: "0000000000",
                password: hashedPassword,
                role: "admin"
            });
            await admin.save();
            console.log("Admin user created successfully");
        } else {
            console.log("Admin user already exists");
        }
    } catch (error) {
        console.error("Error seeding admin user:", error);
    }
};

// Run the seed function to ensure admin exists
seedAdminUser();

// Routes
app.use("/api/auth", authRoutes); // Authentication routes
app.use("/api/appointments", appointmentRoutes); // Appointment routes
app.use("/api/services", serviceRoutes); // Service routes
app.use("/api/users", userRoutes); // User routes

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
