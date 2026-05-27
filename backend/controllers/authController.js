import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import User from '../models/User.js';

const SALT_ROUNDS = 10;
const JWT_EXPIRES_IN = '7d';

/**
 * Generate a short, shareable room ID
 */
const generateRoomId = () => uuidv4().split('-')[0].toUpperCase();

export const signup = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    const user = await User.create({
      username,
      email,
      passwordHash,
    });
    if (!process.env.JWT_SECRET) {
      throw new Error("JWT_SECRET is not configured");
    }
    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    return res.status(201).json({
      token,
      user: { id: user._id, username: user.username, email: user.email },
      roomId: generateRoomId(),
    });
  } catch (error) {
    console.error('[signup error]', error);
    return res.status(500).json({ message: 'Server error during signup' });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+passwordHash');
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    return res.status(200).json({
      token,
      user: { id: user._id, username: user.username, email: user.email },
      roomId: generateRoomId(),
    });
  } catch (error) {
    console.error('[login error]', error);
    return res.status(500).json({ message: 'Server error during login' });
  }
};

export const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).lean();
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.status(200).json(user);
  } catch (error) {
    console.error('[getProfile error]', error);
    return res.status(500).json({ message: 'Server error' });
  }
};

export const updateProfile = async (req, res) => {
  try {
    const { username, email, currentPassword, newPassword, avatar, preferences } = req.body;

    const user = await User.findById(req.user.id).select('+passwordHash');
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Password change
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: 'Current password is required to set a new password.' });
      }
      const isMatch = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!isMatch) return res.status(400).json({ message: 'Current password is incorrect.' });
      if (newPassword.length < 6) return res.status(400).json({ message: 'New password must be at least 6 characters.' });
      user.passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    }

    // Username uniqueness check
    if (username && username !== user.username) {
      const taken = await User.findOne({ username, _id: { $ne: user._id } });
      if (taken) return res.status(409).json({ message: 'Username already taken.' });
      user.username = username;
    }

    // Email uniqueness check
    if (email && email.toLowerCase() !== user.email) {
      const taken = await User.findOne({ email: email.toLowerCase(), _id: { $ne: user._id } });
      if (taken) return res.status(409).json({ message: 'Email already in use.' });
      user.email = email.toLowerCase();
    }

    if (avatar !== undefined) user.avatar = avatar;
    if (preferences) user.preferences = { ...user.preferences, ...preferences };

    await user.save();

    const updated = user.toJSON();
    return res.status(200).json({ message: 'Profile updated successfully.', user: updated });
  } catch (error) {
    console.error('[updateProfile error]', error);
    return res.status(500).json({ message: 'Server error' });
  }
};

export const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;

    if (req.user.id !== id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized to delete this user' });
    }

    const { deleteUserCascade } = await import('../services/deleteUserCascade.js');
    const result = await deleteUserCascade(id);

    return res.status(200).json(result);
  } catch (error) {
    console.error('[delete user error]', error);
    if (error.message === 'User not found') {
      return res.status(404).json({ message: 'User not found' });
    }
    if (error.message === 'Cannot delete system administrator accounts') {
      return res.status(403).json({ message: error.message });
    }
    return res.status(500).json({ message: 'Server error during user deletion' });
  }
};
