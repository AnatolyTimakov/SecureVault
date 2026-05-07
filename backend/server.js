require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path'); // Добавьте эту строку
const { initializeDatabase } = require('./database');

const authRoutes = require('./routes/auth');
const entryRoutes = require('./routes/entries');
const adminRoutes = require('./routes/admin');
const sharingRoutes = require('./routes/sharing');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// CORS настройки
app.use(cors({
  origin: true, // Разрешить все источники для разработки
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.options('*', cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests, please try again later.' },
  skip: () => process.env.NODE_ENV === 'development'
});

app.use('/api/', limiter);

// Body parsing
app.use(express.json({ limit: '50mb' })); // Увеличиваем лимит
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Logging middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// ========== РАЗДАЧА СТАТИЧЕСКИХ ФАЙЛОВ ==========
// Укажите путь к папке с вашим HTML файлом
const frontendPath = path.join(__dirname, '..'); // Если HTML в родительской папке
// ИЛИ если HTML в той же папке что и server.js:
// const frontendPath = __dirname;

app.use(express.static(frontendPath));

// Отдаем index.html для корневого пути
app.get('/', (req, res) => {
  res.sendFile(path.join(frontendPath, 'pwsafe.html'));
});

// ========== API РОУТЫ ==========
app.use('/api/auth', authRoutes);
app.use('/api/entries', entryRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/sharing', sharingRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), port: PORT });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error', message: err.message });
});

// 404 handler for API
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found', path: req.path });
});

// Start server
async function startServer() {
  try {
    await initializeDatabase();
    console.log('✅ Database initialized successfully');
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`\n🔐 SecureVault backend running on port ${PORT}`);
      console.log(`📍 API: http://localhost:${PORT}/api`);
      console.log(`🏠 Frontend: http://localhost:${PORT}/pwsafe.html`);
      console.log(`🏥 Health: http://localhost:${PORT}/api/health\n`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();