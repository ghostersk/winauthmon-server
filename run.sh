#!/bin/bash
# Start the application using the built-in uvicorn setup
# Configuration is now read from config.ini

#source ~/Documents/Projects/domain-logons/.venv/bin/activate && python app.py

source .venv/bin/activate && python app.py
# Legacy way to start with explicit uvicorn command (no longer needed):
# source ~/Documents/Projects/domain-logons/.venv/bin/activate && uvicorn app:wsg --host 0.0.0.0 --port 8000 \
#    --reload --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem

# Run Flask app with Hypercorn (alternative ASGI server):
# hypercorn app:wsg --keyfile=certs/key.pem \
#    --certfile=certs/cert.pem --bind "0.0.0.0:8000"