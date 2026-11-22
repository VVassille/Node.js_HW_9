import express from "express";
import bcrypt from "bcrypt";
import User from "../models/User.js";
import jwt from "jsonwebtoken";
import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";

const router = express.Router();

// POST /register
router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check required fields
    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        message: "Email is already registered",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = await User.create({
      email,
      password: hashedPassword,
    });

    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: newUser._id,
        email: newUser.email,
      },
    });
  } catch (error) {
    res.status(500).json({
      message: "Server error",
      error: error.message,
    });
  }
});
// POST /login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.status(200).json({
      message: "Login successful",
      token,
      mustChangePassword: user.mustChangePassword,
    });
  } catch (error) {
    res.status(500).json({
      message: "Server error",
      error: error.message,
    });
  }
});
// POST /change-password
router.post("/change-password", authMiddleware, async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword) {
      return res.status(400).json({
        message: "New password is required",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    req.user.password = hashedPassword;
    req.user.mustChangePassword = false;

    await req.user.save();

    res.status(200).json({
      message: "Password changed successfully",
    });
  } catch (error) {
    res.status(500).json({
      message: "Server error",
      error: error.message,
    });
  }
});
// POST /delete-account
router.post("/delete-account", authMiddleware, async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        message: "Password is required",
      });
    }

    const isPasswordValid = await bcrypt.compare(password, req.user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Incorrect password",
      });
    }

    await User.findByIdAndDelete(req.user._id);

    res.status(200).json({
      message: "Account deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      message: "Server error",
      error: error.message,
    });
  }
});
// GET /admin
router.get("/admin", authMiddleware, roleMiddleware("admin"), (req, res) => {
  res.status(200).json({
    message: "Welcome to the admin panel",
    user: req.user.email,
    role: req.user.role,
  });
});
// POST /change-email
router.post("/change-email", authMiddleware, async (req, res) => {
  try {
    const { newEmail, password } = req.body;

    if (!newEmail || !password) {
      return res.status(400).json({
        message: "New email and password are required",
      });
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(password, req.user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Incorrect password",
      });
    }

    // Check if email already exists
    const existingUser = await User.findOne({
      email: newEmail.toLowerCase(),
    });

    if (existingUser) {
      return res.status(409).json({
        message: "Email is already registered",
      });
    }

    // Update email
    req.user.email = newEmail.toLowerCase();
    await req.user.save();

    res.status(200).json({
      message: "Email changed successfully",
      email: req.user.email,
    });
  } catch (error) {
    res.status(500).json({
      message: "Server error",
      error: error.message,
    });
  }
});
export default router;
