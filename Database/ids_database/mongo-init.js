// mongo-init.js
// runs on first container startup to prepare the `ids` database
db = db.getSiblingDB('ids');

try {
  db.createCollection('alerts');
} catch (e) {
  // ignore if exists
}

// index for fast queries by timestamp
db.alerts.createIndex({ timestamp: 1 });
