const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const User = require('../models/User');
const Project = require('../models/Project');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const {
  deleteProjectArchive,
  deleteProjectFolder
} = require('../services/storage/supabaseStorageService');
const generateToken = require('../utils/generateToken');

// Email regex pattern for validation
const EMAIL_REGEX = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;

/**
 * @desc    Register a new user
 * @route   POST /api/auth/register
 * @access  Public
 */
const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // 1. Validate required fields
    if (!name || !email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide name, email, and password'
      });
    }

    // 2. Validate email format
    const trimmedEmail = email.trim().toLowerCase();
    if (!EMAIL_REGEX.test(trimmedEmail)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide a valid email address'
      });
    }

    // 3. Validate password length
    if (typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({
        status: 'fail',
        message: 'Password must be at least 6 characters long'
      });
    }

    // 4. Check for existing user (prevent duplicate email)
    const existingUser = await User.findOne({ email: trimmedEmail });
    if (existingUser) {
      return res.status(409).json({
        status: 'fail',
        message: 'An account with this email already exists'
      });
    }

    // 5. Hash password securely using bcrypt
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // 6. Create user in database
    const user = await User.create({
      name: name.trim(),
      email: trimmedEmail,
      password: hashedPassword
    });

    // 7. Generate JWT token
    const token = generateToken(user._id);

    // 8. Send response without exposing password hash
    return res.status(201).json({
      status: 'success',
      message: 'User registered successfully',
      data: {
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          createdAt: user.createdAt
        },
        token
      }
    });
  } catch (error) {
    console.error(`[AEGISOR Auth Error] Register: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error during registration'
    });
  }
};

/**
 * @desc    Authenticate user & return JWT token
 * @route   POST /api/auth/login
 * @access  Public
 */
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Validate required fields
    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide both email and password'
      });
    }

    const trimmedEmail = email.trim().toLowerCase();

    // 2. Look up user by email
    const user = await User.findOne({ email: trimmedEmail });
    if (!user) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid email or password'
      });
    }

    // 3. Verify password against stored hash
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid email or password'
      });
    }

    // 4. Generate JWT token
    const token = generateToken(user._id);

    // 5. Send response without exposing password hash
    return res.status(200).json({
      status: 'success',
      message: 'Login successful',
      data: {
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          createdAt: user.createdAt
        },
        token
      }
    });
  } catch (error) {
    console.error(`[AEGISOR Auth Error] Login: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error during login'
    });
  }
};

/**
 * @desc    Get current authenticated user profile
 * @route   GET /api/auth/me
 * @access  Private (Protected by JWT)
 */
const getMe = async (req, res) => {
  try {
    return res.status(200).json({
      status: 'success',
      data: {
        user: req.user
      }
    });
  } catch (error) {
    console.error(`[AEGISOR Auth Error] GetMe: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error fetching user profile'
    });
  }
};

/**
 * @desc    Update current user profile (name, email)
 * @route   PUT /api/auth/profile
 * @access  Private
 */
const updateProfile = async (req, res) => {
  try {
    const { name, email } = req.body;
    const updates = {};

    if (name) {
      if (typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({
          status: 'fail',
          message: 'Valid name is required'
        });
      }
      updates.name = name.trim();
    }

    if (email) {
      const trimmedEmail = email.trim().toLowerCase();
      if (!EMAIL_REGEX.test(trimmedEmail)) {
        return res.status(400).json({
          status: 'fail',
          message: 'Please provide a valid email address'
        });
      }

      // Check if email already in use by another user
      if (trimmedEmail !== req.user.email) {
        const existing = await User.findOne({ email: trimmedEmail });
        if (existing) {
          return res.status(409).json({
            status: 'fail',
            message: 'Email address is already in use by another account'
          });
        }
        updates.email = trimmedEmail;
      }
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { $set: updates },
      { returnDocument: 'after', runValidators: true }
    ).select('-password');

    return res.status(200).json({
      status: 'success',
      message: 'Profile updated successfully',
      data: {
        user: updatedUser
      }
    });
  } catch (error) {
    console.error(`[AEGISOR Auth Error] UpdateProfile: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error updating profile'
    });
  }
};

/**
 * @desc    Change password
 * @route   PUT /api/auth/password
 * @access  Private
 */
const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide both currentPassword and newPassword'
      });
    }

    if (typeof newPassword !== 'string' || newPassword.length < 6) {
      return res.status(400).json({
        status: 'fail',
        message: 'New password must be at least 6 characters long'
      });
    }

    // Retrieve full user including password
    const user = await User.findById(req.user._id);
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({
        status: 'fail',
        message: 'Current password is incorrect'
      });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    return res.status(200).json({
      status: 'success',
      message: 'Password changed successfully'
    });
  } catch (error) {
    console.error(`[AEGISOR Auth Error] ChangePassword: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error changing password'
    });
  }
};

/**
 * @desc    Delete user account and cascade delete all associated data
 * @route   DELETE /api/auth/account
 * @access  Private
 */
const deleteAccount = async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Password is required to confirm account deletion'
      });
    }

    const user = await User.findById(req.user._id);
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid password. Account deletion aborted'
      });
    }

    // 1. Find all projects belonging to user
    const projects = await Project.find({ owner: user._id });
    const projectIds = projects.map((p) => p._id);

    // 2. Clean up extracted upload files on disk and in Supabase Storage
    for (const project of projects) {
      if (project.extractedPath && fs.existsSync(project.extractedPath)) {
        try {
          fs.rmSync(project.extractedPath, { recursive: true, force: true });
        } catch (fileErr) {
          console.warn(`[Cleanup Warning] Could not remove ${project.extractedPath}: ${fileErr.message}`);
        }
      }
      try {
        if (project.storageKey) {
          await deleteProjectArchive(project.storageKey);
        }
        await deleteProjectFolder(project._id.toString());
      } catch (storageErr) {
        console.warn(`[Supabase Cleanup Warning] Could not remove archives for ${project._id}: ${storageErr.message}`);
      }
    }

    // 3. Delete all associated vulnerabilities and scans
    if (projectIds.length > 0) {
      await Vulnerability.deleteMany({ project: { $in: projectIds } });
      await Scan.deleteMany({ project: { $in: projectIds } });
      await Project.deleteMany({ owner: user._id });
    }

    // 4. Delete user record
    await User.findByIdAndDelete(user._id);

    return res.status(200).json({
      status: 'success',
      message: 'Account and all associated project data have been permanently deleted'
    });
  } catch (error) {
    console.error(`[AEGISOR Auth Error] DeleteAccount: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error during account deletion'
    });
  }
};

module.exports = {
  register,
  login,
  getMe,
  updateProfile,
  changePassword,
  deleteAccount
};
