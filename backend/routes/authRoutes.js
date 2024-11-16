// authRoutes.js
const express = require("express");
const { register, login, updateUser } = require("../controllers/authController");
const { verifyToken } = require("../middleware/authMiddleware");
const router = express.Router();

router.post("/signup", register); // POST route for signup
router.post("/login", (req, res) => {
    req.body.isAdmin = false; // Regular user login
    login(req, res);
});
router.post("/admin/login", (req, res) => {
    req.body.isAdmin = true; // Admin login
    login(req, res);
});
router.put("/update", verifyToken, updateUser); // PUT route for updating profile

module.exports = router;
