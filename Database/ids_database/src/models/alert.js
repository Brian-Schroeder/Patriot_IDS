const mongoose = require('mongoose');

const AlertStatus = {
  NEW: 'new',
  ACKNOWLEDGED: 'acknowledged',
  RESOLVED: 'resolved',
  FALSE_POSITIVE: 'false_positive'
};

const AlertSchema = new mongoose.Schema({
  time: { type: Date, default: Date.now },
  severity: { type: String, default: 'None' },
  type: { type: String, default: 'None' },
  source: { type: String },
  destination: { type: String },
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

module.exports = mongoose.model('Alert', AlertSchema);
