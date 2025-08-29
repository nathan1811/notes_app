const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();

// Enhanced CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? false : ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost:5000'],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));

// In-memory storage (walking skeleton)
const storage = {
  users: [],
  notes: []
};

// Storage Module - Abstraction for data persistence
const StorageModule = {
  save(collection, data) {
    const id = Date.now().toString() + Math.random().toString(36).substr(2, 9);
    const item = { id, ...data, createdAt: new Date().toISOString() };
    storage[collection].push(item);
    return item;
  },
  
  find(collection, query) {
    return storage[collection].filter(item => {
      return Object.keys(query).every(key => item[key] === query[key]);
    });
  },
  
  findOne(collection, query) {
    return this.find(collection, query)[0] || null;
  },
  
  update(collection, id, data) {
    const index = storage[collection].findIndex(item => item.id === id);
    if (index !== -1) {
      storage[collection][index] = { 
        ...storage[collection][index], 
        ...data,
        updatedAt: new Date().toISOString()
      };
      return storage[collection][index];
    }
    return null;
  },
  
  delete(collection, id) {
    const index = storage[collection].findIndex(item => item.id === id);
    if (index !== -1) {
      storage[collection].splice(index, 1);
      return { success: true };
    }
    return { success: false };
  }
};

// User Module - User management operations
const UserModule = {
  createUser(email, hashedPassword) {
    return StorageModule.save('users', { 
      email: email.toLowerCase().trim(), 
      password: hashedPassword 
    });
  },
  
  findUserByEmail(email) {
    return StorageModule.findOne('users', { email: email.toLowerCase().trim() });
  },
  
  findUserById(userId) {
    return StorageModule.findOne('users', { id: userId });
  }
};

// Auth Module - Authentication operations
const AuthModule = {
  async register(email, password) {
    // Validation
    if (!email || !password) {
      return { success: false, message: 'Email and password are required' };
    }
    
    if (password.length < 6) {
      return { success: false, message: 'Password must be at least 6 characters' };
    }
    
    // Check if email is valid
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email.trim())) {
      return { success: false, message: 'Invalid email format' };
    }
    
    // Check if user exists
    if (UserModule.findUserByEmail(email)) {
      return { success: false, message: 'User already exists' };
    }
    
    try {
      // Hash password and create user
      const hashedPassword = await bcrypt.hash(password, 12); // Increased salt rounds
      const user = UserModule.createUser(email, hashedPassword);
      
      return { 
        success: true, 
        message: 'User registered successfully',
        userId: user.id 
      };
    } catch (error) {
      console.error('Registration error:', error);
      return { success: false, message: 'Registration failed' };
    }
  },
  
  async login(email, password) {
    // Validation
    if (!email || !password) {
      return { success: false, message: 'Email and password are required' };
    }
    
    try {
      // Find user
      const user = UserModule.findUserByEmail(email);
      if (!user) {
        return { success: false, message: 'Invalid credentials' };
      }
      
      // Verify password
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        return { success: false, message: 'Invalid credentials' };
      }
      
      // Generate token
      const token = jwt.sign(
        { userId: user.id, email: user.email }, 
        process.env.JWT_SECRET || 'SECRET_KEY_WALKING_SKELETON', 
        { expiresIn: '24h' }
      );
      
      return { 
        success: true, 
        token,
        message: 'Login successful'
      };
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, message: 'Login failed' };
    }
  },
  
  verifyToken(token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'SECRET_KEY_WALKING_SKELETON');
      return { valid: true, userId: decoded.userId, email: decoded.email };
    } catch (error) {
      return { valid: false, message: 'Invalid or expired token' };
    }
  }
};

// Notes Module - Note management operations
const NotesModule = {
  createNote(userId, title, body) {
    // Validation
    if (!title || !body) {
      throw new Error('Title and body are required');
    }
    
    if (title.trim().length === 0 || body.trim().length === 0) {
      throw new Error('Title and body cannot be empty');
    }
    
    return StorageModule.save('notes', {
      userId,
      title: title.trim().substring(0, 200), // Increased limit and trim
      body: body.trim(),
      createdAt: new Date().toISOString()
    });
  },
  
  getNotesByUser(userId) {
    const notes = StorageModule.find('notes', { userId });
    // Sort by creation date (newest first)
    return notes.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  },
  
  getNoteById(noteId) {
    return StorageModule.findOne('notes', { id: noteId });
  },
  
  updateNote(noteId, userId, title, body) {
    const note = StorageModule.findOne('notes', { id: noteId });
    
    if (!note) {
      return null;
    }
    
    if (note.userId !== userId) {
      throw new Error('Unauthorized to update this note');
    }
    
    if (!title || !body) {
      throw new Error('Title and body are required');
    }
    
    if (title.trim().length === 0 || body.trim().length === 0) {
      throw new Error('Title and body cannot be empty');
    }
    
    return StorageModule.update('notes', noteId, { 
      title: title.trim().substring(0, 200), 
      body: body.trim()
    });
  },
  
  deleteNote(noteId, userId) {
    const note = StorageModule.findOne('notes', { id: noteId });
    
    if (!note) {
      return { success: false, message: 'Note not found' };
    }
    
    if (note.userId !== userId) {
      return { success: false, message: 'Unauthorized to delete this note' };
    }
    
    return StorageModule.delete('notes', noteId);
  }
};

// Middleware - Authentication middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization;
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const result = AuthModule.verifyToken(token);
  
  if (result.valid) {
    req.userId = result.userId;
    req.userEmail = result.email;
    next();
  } else {
    res.status(401).json({ error: result.message || 'Unauthorized' });
  }
};

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Routes - API endpoints

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    storage: {
      users: storage.users.length,
      notes: storage.notes.length
    },
    uptime: process.uptime()
  });
});

// Authentication routes
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }
    
    const result = await AuthModule.register(email, password);
    res.status(result.success ? 201 : 400).json(result);
  } catch (error) {
    console.error('Register endpoint error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }
    
    const result = await AuthModule.login(email, password);
    res.status(result.success ? 200 : 401).json(result);
  } catch (error) {
    console.error('Login endpoint error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Note routes (protected)
app.post('/add_note', authMiddleware, (req, res) => {
  try {
    const { title, body } = req.body;
    
    if (!title || !body) {
      return res.status(400).json({ success: false, message: 'Title and body are required' });
    }
    
    const note = NotesModule.createNote(req.userId, title, body);
    res.status(201).json({ success: true, note });
  } catch (error) {
    console.error('Add note error:', error);
    res.status(400).json({ success: false, message: error.message });
  }
});

app.get('/list_notes', authMiddleware, (req, res) => {
  try {
    const notes = NotesModule.getNotesByUser(req.userId);
    res.json(notes);
  } catch (error) {
    console.error('List notes error:', error);
    res.status(500).json({ error: 'Failed to fetch notes' });
  }
});

app.get('/note/:id', authMiddleware, (req, res) => {
  try {
    const noteId = req.params.id;
    
    if (!noteId) {
      return res.status(400).json({ error: 'Note ID is required' });
    }
    
    const note = NotesModule.getNoteById(noteId);
    
    if (!note) {
      return res.status(404).json({ error: 'Note not found' });
    }
    
    if (note.userId !== req.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    res.json(note);
  } catch (error) {
    console.error('Get note error:', error);
    res.status(500).json({ error: 'Failed to fetch note' });
  }
});

app.put('/update_note/:id', authMiddleware, (req, res) => {
  try {
    const { title, body } = req.body;
    const noteId = req.params.id;
    
    if (!noteId) {
      return res.status(400).json({ success: false, message: 'Note ID is required' });
    }
    
    if (!title || !body) {
      return res.status(400).json({ success: false, message: 'Title and body are required' });
    }
    
    const note = NotesModule.updateNote(noteId, req.userId, title, body);
    
    if (note) {
      res.json({ success: true, note });
    } else {
      res.status(404).json({ success: false, message: 'Note not found' });
    }
  } catch (error) {
    console.error('Update note error:', error);
    const statusCode = error.message.includes('Unauthorized') ? 403 : 400;
    res.status(statusCode).json({ 
      success: false, 
      message: error.message 
    });
  }
});

app.delete('/delete_note/:id', authMiddleware, (req, res) => {
  try {
    const noteId = req.params.id;
    
    if (!noteId) {
      return res.status(400).json({ success: false, message: 'Note ID is required' });
    }
    
    const result = NotesModule.deleteNote(noteId, req.userId);
    res.status(result.success ? 200 : 404).json(result);
  } catch (error) {
    console.error('Delete note error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete note' });
  }
});

// Serve static files from current directory (where index.html is located)
app.use(express.static(__dirname));

// Serve index.html for root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Handle 404 for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// Catch-all handler: send back React's index.html file for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Global error handler:', err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

// Start server
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  console.log(`
    ╔══════════════════════════════════════╗
    ║                                      ║
    ║   📝 Notes App Server                ║
    ║   Running on port ${PORT}                ║
    ║   http://localhost:${PORT}               ║
    ║                                      ║
    ║   Environment: ${process.env.NODE_ENV || 'development'}           ║
    ║   Time: ${new Date().toLocaleString()}    ║
    ║                                      ║
    ╚══════════════════════════════════════╝
  `);
});

// Handle server startup errors
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Please choose a different port.`);
  } else {
    console.error('Server startup error:', err);
  }
  process.exit(1);
});
