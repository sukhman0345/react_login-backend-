const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

// User Profile (Protected Route)
router.get("/users/profile", authMiddleware, (req, res) => {
  res.json({ message: "Welcome to your profile!", user: req.user });
});

//  Register Route (Fix: Prevent duplicate users)
router.post("/users/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists!" });
    }

    // Hash password before saving
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login Route (Fix: Debugging + Ensure JWT Secret Exists)
router.post("/users/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ username });
    if (!user) {
      console.log(" User not found!");
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log(" Incorrect password!");
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Generate JWT Token
    if (!process.env.JWT_SECRET) {
      console.log("Missing JWT_SECRET in .env file!");
      return res.status(500).json({ message: "Server error: Missing JWT_SECRET" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({ token, username: user.username });
  } catch (error) {
    console.log(" Server error:", error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
