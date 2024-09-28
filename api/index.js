require('dotenv').config({ path: '../.env' });
const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

// Import Models
const User = require('./models/User');
const Post = require('./models/Post');

// Initialize Express App
const app = express();

// Use Multer for File Uploads
const uploadMiddleware = multer({ dest: 'uploads/' });

// Load environment variables
const MONGOSTR = process.env.MONGOSTR;
const JWT_SECRET = process.env.JWT_SECRET || 'defaultsecret'; // Fallback to a default value if not provided
const PORT = process.env.PORT || 4000;

// Middleware
app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Connect to MongoDB
mongoose.connect(MONGOSTR, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// JWT and Bcrypt Settings
const salt = bcrypt.genSaltSync(10);

// Routes

// Registration Route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = bcrypt.hashSync(password, salt);
    const userDoc = await User.create({ username, password: hashedPassword });
    res.json(userDoc);
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: 'Failed to register user.' });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.findOne({ username });
    if (!userDoc) {
      return res.status(400).json({ error: 'User not found.' });
    }
    const passOk = bcrypt.compareSync(password, userDoc.password);
    if (passOk) {
      const token = jwt.sign({ username, id: userDoc._id }, JWT_SECRET);
      res.cookie('token', token).json({ id: userDoc._id, username });
    } else {
      res.status(400).json({ error: 'Wrong credentials.' });
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed.' });
  }
});

// Profile Route
app.get('/profile', (req, res) => {
  const { token } = req.cookies;
  jwt.verify(token, JWT_SECRET, (err, info) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    res.json(info);
  });
});

// Logout Route
app.post('/logout', (req, res) => {
  res.cookie('token', '', { maxAge: 0 }).json('Logged out successfully');
});

// Create Post Route
app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
  const { originalname, path: tempPath } = req.file;
  const ext = originalname.split('.').pop();
  const newPath = `${tempPath}.${ext}`;
  fs.renameSync(tempPath, newPath);

  const { token } = req.cookies;
  jwt.verify(token, JWT_SECRET, async (err, info) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    const { title, summary, content } = req.body;
    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover: newPath,
      author: info.id,
    });
    res.json(postDoc);
  });
});

// Update Post Route
app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
  let newPath = null;
  if (req.file) {
    const { originalname, path: tempPath } = req.file;
    const ext = originalname.split('.').pop();
    newPath = `${tempPath}.${ext}`;
    fs.renameSync(tempPath, newPath);
  }

  const { token } = req.cookies;
  jwt.verify(token, JWT_SECRET, async (err, info) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    const { id, title, summary, content } = req.body;
    const postDoc = await Post.findById(id);
    if (!postDoc) return res.status(404).json({ error: 'Post not found' });
    
    const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
    if (!isAuthor) return res.status(403).json({ error: 'You are not the author' });

    await postDoc.update({
      title,
      summary,
      content,
      cover: newPath ? newPath : postDoc.cover,
    });
    res.json(postDoc);
  });
});

// Get All Posts Route
app.get('/post', async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('author', ['username'])
      .sort({ createdAt: -1 })
      .limit(20);
    res.json(posts);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to retrieve posts.' });
  }
});

// Get Single Post by ID
app.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const postDoc = await Post.findById(id).populate('author', ['username']);
    if (!postDoc) return res.status(404).json({ error: 'Post not found' });
    res.json(postDoc);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to retrieve post.' });
  }
});

// Start the Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
