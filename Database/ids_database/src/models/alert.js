const mongoose = require('mongoose');

const AlertStatus = {
  NEW: 'new',
  ACKNOWLEDGED: 'acknowledged',
  RESOLVED: 'resolved',
  FALSE_POSITIVE: 'false_positive'
};

const AlertSchema = new mongoose.Schema({
  id: { type: String, unique: true, sparse: true },
  time: { type: Date, default: Date.now },
  timestamp: { type: Date, default: Date.now },
  severity: { type: String, default: 'None' },
  type: { type: String, default: 'None' },
  source: { type: String },
  destination: { type: String },
  destinationPort: { type: Number },
  description: { type: String },
  status: { type: String, default: 'new', enum: Object.values(AlertStatus) },
  packets: { type: Number, default: 0 },
  anomaly: { type: Number, default: -1 },
  metadata: { type: mongoose.Schema.Types.Mixed }
}, {
  versionKey: false,
  toJSON: {
    transform: function(doc, ret) {
      if (ret && ret.status) delete ret.status;
      if (ret && ret.__v) delete ret.__v;
      return ret;
    }
  },
  toObject: {
    transform: function(doc, ret) {
      if (ret && ret.status) delete ret.status;
      if (ret && ret.__v) delete ret.__v;
      return ret;
    }
  }
});

// Index for fast queries by timestamp
AlertSchema.index({ timestamp: -1 });
AlertSchema.index({ time: -1 });

module.exports = mongoose.model('Alert', AlertSchema);
