const express = require('express');
const mongoose = require('mongoose');
const morgan = require('morgan');
const cors = require('cors');
require('dotenv').config();

const alertsRouter = require('./routes/alerts');
// flowLogs router exposes flow log documents from a separate DB/collection
const flowLogsRouter = require('./routes/flowLogs');

const app = express();
app.use(morgan('dev'));
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/ids';

// Helpful util to map mongoose connection state to human-readable status
function dbState() {
  // 0 = disconnected, 1 = connected, 2 = connecting, 3 = disconnecting
  const s = mongoose.connection.readyState;
  switch (s) {
    case 0: return 'disconnected';
    case 1: return 'connected';
    case 2: return 'connecting';
    case 3: return 'disconnecting';
    default: return 'unknown';
  }
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', db: dbState() });
});

// Connect to MongoDB first, then mount routes and start listening.
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to MongoDB');
    app.use('/alerts', alertsRouter);
    app.use('/flowLogs', flowLogsRouter);

    app.listen(PORT, () => {
      console.log(`IDS database service listening on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    // keep the process alive for easier debugging (don't exit immediately)
    // so logs can be inspected and container restarted after fix
  });

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});
