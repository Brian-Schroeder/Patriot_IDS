const express = require('express');
const router = express.Router();
const Alert = require('../models/alert');

router.post('/', async (req, res) => {
  try {
    const body = req.body;
    // Normalize: ensure time/timestamp from incoming timestamp
    if (body.timestamp && !body.time) body.time = new Date(body.timestamp);
    if (body.time && !body.timestamp) body.timestamp = new Date(body.time);
    const a = new Alert(body);
    const saved = await a.save();
    res.status(201).json(saved);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 1000);
    const items = await Alert.find().sort({ time: -1 }).limit(limit);
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const item = await Alert.findById(req.params.id);
    if (!item) return res.status(404).json({ error: 'Not found' });
    res.json(item);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
