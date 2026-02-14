import os
from datetime import timedelta

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
    
    # Database
    DATABASE_URI = os.environ.get('DATABASE_URI', 'sqlite:///ids.db')
    
    # Detection thresholds
    PACKET_RATE_THRESHOLD = 1000      # packets per second
    CONNECTION_THRESHOLD = 100         # connections from single IP
    FAILED_LOGIN_THRESHOLD = 5         # failed attempts before alert
    PORT_SCAN_THRESHOLD = 20           # ports scanned in time window
    TIME_WINDOW = timedelta(minutes=1) # analysis window
    
    # Alert settings
    ALERT_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    LOG_FILE = 'ids_alerts.log'
    
    # Network interface to monitor
    NETWORK_INTERFACE = os.environ.get('NETWORK_INTERFACE', 'eth0')