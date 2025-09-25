const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(express.json());
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/streamshare', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// User Schema
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  bio: { type: String, default: '' },
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  totalViews: { type: Number, default: 0 },
  isLive: { type: Boolean, default: false },
  currentStreamId: { type: String, default: null },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// Stream Schema
const StreamSchema = new mongoose.Schema({
  streamId: { type: String, required: true, unique: true },
  title: { type: String, required: true },
  category: { type: String, required: true },
  streamer: { type: String, required: true },
  streamerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  viewers: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  startTime: { type: Date, default: Date.now },
  endTime: { type: Date, default: null }
});

const Stream = mongoose.model('Stream', StreamSchema);

// In-memory storage for active streams and connections
const activeStreams = new Map();
const streamConnections = new Map();
const userSockets = new Map();

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  } catch (err) {
    return res.sendStatus(403);
  }
};

// Auth Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, bio } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      bio: bio || ''
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        bio: user.bio,
        followers: user.followers.length,
        totalViews: user.totalViews
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        bio: user.bio,
        followers: user.followers.length,
        totalViews: user.totalViews,
        isLive: user.isLive
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Stream Routes
app.get('/api/streams', async (req, res) => {
  try {
    const streams = await Stream.find({ isActive: true })
      .populate('streamerId', 'username')
      .sort({ viewers: -1 });

    const formattedStreams = streams.map(stream => ({
      id: stream.streamId,
      title: stream.title,
      streamer: stream.streamer,
      category: stream.category,
      viewers: activeStreams.get(stream.streamId)?.viewers || 0,
      isLive: activeStreams.has(stream.streamId),
      startTime: stream.startTime
    }));

    res.json(formattedStreams);
  } catch (error) {
    console.error('Error fetching streams:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/streams/start', authenticateToken, async (req, res) => {
  try {
    const { title, category } = req.body;
    const user = req.user;

    // Check if user is already streaming
    if (user.isLive) {
      return res.status(400).json({ error: 'You are already streaming' });
    }

    const streamId = `stream_${user._id}_${Date.now()}`;

    // Create stream record
    const stream = new Stream({
      streamId,
      title,
      category,
      streamer: user.username,
      streamerId: user._id
    });

    await stream.save();

    // Update user status
    user.isLive = true;
    user.currentStreamId = streamId;
    await user.save();

    // Add to active streams
    activeStreams.set(streamId, {
      streamId,
      title,
      category,
      streamer: user.username,
      streamerId: user._id,
      viewers: 0,
      startTime: Date.now(),
      connections: new Set()
    });

    res.json({ streamId, message: 'Stream started successfully' });
  } catch (error) {
    console.error('Error starting stream:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/streams/end', authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    if (!user.isLive || !user.currentStreamId) {
      return res.status(400).json({ error: 'No active stream found' });
    }

    const streamId = user.currentStreamId;

    // End stream in database
    await Stream.findOneAndUpdate(
      { streamId },
      { isActive: false, endTime: new Date() }
    );

    // Update user status
    user.isLive = false;
    user.currentStreamId = null;
    await user.save();

    // Remove from active streams
    const streamData = activeStreams.get(streamId);
    if (streamData) {
      // Notify all viewers that stream ended
      io.to(streamId).emit('stream-ended');
      activeStreams.delete(streamId);
    }

    res.json({ message: 'Stream ended successfully' });
  } catch (error) {
    console.error('Error ending stream:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/user/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userInfo = {
      username: user.username,
      bio: user.bio,
      followers: user.followers.length,
      totalViews: user.totalViews,
      isLive: user.isLive,
      currentStreamId: user.currentStreamId
    };

    if (user.isLive && user.currentStreamId) {
      const streamData = activeStreams.get(user.currentStreamId);
      if (streamData) {
        userInfo.stream = {
          id: streamData.streamId,
          title: streamData.title,
          category: streamData.category,
          viewers: streamData.viewers
        };
      }
    }

    res.json(userInfo);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Socket.IO WebRTC Signaling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Store user socket mapping
  socket.on('user-connected', (userData) => {
    if (userData && userData.userId) {
      userSockets.set(userData.userId, socket.id);
      socket.userId = userData.userId;
      socket.username = userData.username;
    }
  });

  // Stream signaling
  socket.on('start-stream', (data) => {
    const { streamId } = data;
    const streamData = activeStreams.get(streamId);
    
    if (streamData && socket.userId === streamData.streamerId.toString()) {
      socket.join(streamId);
      socket.streamId = streamId;
      socket.isStreamer = true;
      
      if (!streamConnections.has(streamId)) {
        streamConnections.set(streamId, new Set());
      }
      
      console.log(`Streamer ${socket.username} started broadcasting ${streamId}`);
    }
  });

  // Join stream as viewer
  socket.on('join-stream', (data) => {
    const { streamId } = data;
    const streamData = activeStreams.get(streamId);
    
    if (streamData) {
      socket.join(streamId);
      socket.streamId = streamId;
      
      if (!streamConnections.has(streamId)) {
        streamConnections.set(streamId, new Set());
      }
      
      streamConnections.get(streamId).add(socket.id);
      streamData.viewers = streamConnections.get(streamId).size;
      
      // Notify streamer of new viewer
      socket.to(streamId).emit('viewer-joined', {
        viewerId: socket.id,
        username: socket.username,
        totalViewers: streamData.viewers
      });
      
      // Send current viewer count to all
      io.to(streamId).emit('viewer-count-update', streamData.viewers);
      
      console.log(`Viewer ${socket.username || socket.id} joined stream ${streamId}`);
    }
  });

  // WebRTC signaling
  socket.on('offer', (data) => {
    socket.to(data.target).emit('offer', {
      offer: data.offer,
      sender: socket.id
    });
  });

  socket.on('answer', (data) => {
    socket.to(data.target).emit('answer', {
      answer: data.answer,
      sender: socket.id
    });
  });

  socket.on('ice-candidate', (data) => {
    socket.to(data.target).emit('ice-candidate', {
      candidate: data.candidate,
      sender: socket.id
    });
  });

  // Chat functionality
  socket.on('chat-message', (data) => {
    const { streamId, message } = data;
    
    if (socket.streamId === streamId) {
      const chatMessage = {
        id: Date.now(),
        username: socket.username || 'Anonymous',
        message: message.substring(0, 500), // Limit message length
        timestamp: Date.now()
      };
      
      io.to(streamId).emit('chat-message', chatMessage);
    }
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    
    // Remove from user sockets mapping
    if (socket.userId) {
      userSockets.delete(socket.userId);
    }
    
    // Handle stream disconnection
    if (socket.streamId) {
      const streamData = activeStreams.get(socket.streamId);
      const connections = streamConnections.get(socket.streamId);
      
      if (connections) {
        connections.delete(socket.id);
        
        if (streamData) {
          streamData.viewers = connections.size;
          
          // Update viewer count for remaining viewers
          io.to(socket.streamId).emit('viewer-count-update', streamData.viewers);
          
          // If streamer disconnected, end the stream
          if (socket.isStreamer) {
            io.to(socket.streamId).emit('stream-ended');
            activeStreams.delete(socket.streamId);
            streamConnections.delete(socket.streamId);
            
            // Update database
            Stream.findOneAndUpdate(
              { streamId: socket.streamId },
              { isActive: false, endTime: new Date() }
            ).exec();
            
            User.findByIdAndUpdate(
              streamData.streamerId,
              { isLive: false, currentStreamId: null }
            ).exec();
          }
        }
      }
    }
  });
});

// Serve channel pages
app.get('/stream/:username', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Catch all route for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`StreamShare server running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to access the application`);
});