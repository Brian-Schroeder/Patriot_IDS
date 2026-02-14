const mongoose = require('mongoose');

const AlertStatus = {
  NEW: 'new',
  ACKNOWLEDGED: 'acknowledged',
  RESOLVED: 'resolved',
  FALSE_POSITIVE: 'false_positive'
};

const AlertSchema = new mongoose.Schema({
  alert_type: { type: String, required: true },
  source_ip: { type: String, required: true },
  destination_ip: { type: String },
  destination_port: { type: Number },
  description: { type: String },
  level: { type: String },
  status: { type: String, default: AlertStatus.NEW },
  timestamp: { type: Date, default: Date.now },
  metadata: { type: mongoose.Schema.Types.Mixed }
});

module.exports = mongoose.model('Alert', AlertSchema);
