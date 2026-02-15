const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();

// DB and collection names can be configured via env:
// FLOW_DB_NAME (default: 'vpcLogs') and FLOW_COLLECTION (default: 'flowLogs')
// Defaults read from the existing DB named `vpcLogs` and collection `flowLogs`.
const FLOW_DB_NAME = process.env.FLOW_DB_NAME || 'vpcLogs';
const FLOW_COLLECTION = process.env.FLOW_COLLECTION || 'flowLogs';

// Use the same MongoDB cluster but switch to the configured logical database
const flowDb = mongoose.connection.useDb(FLOW_DB_NAME);

// Flexible schema to accept existing flow log documents without enforcing fields
const FlowLogSchema = new mongoose.Schema({}, { strict: false, timestamps: false });
const FlowLog = flowDb.model('FlowLog', FlowLogSchema, FLOW_COLLECTION);

router.get('/', async (req, res) => {
  try {
    const items = await FlowLog.find().sort({ time: -1 }).limit(200);
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
