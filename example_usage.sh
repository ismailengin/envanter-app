#!/bin/bash
# Example usage of discovery.py with FastAPI backend

# Run discovery script and send to API
python3 discovery.py | curl -X POST http://localhost:8000/api/v1/discovery \
  -H "Content-Type: application/json" \
  -d @-

# Or save to file first, then send
python3 discovery.py > discovery_output.json
curl -X POST http://localhost:8000/api/v1/discovery \
  -H "Content-Type: application/json" \
  -d @discovery_output.json

# Query apps summary
curl http://localhost:8000/api/v1/apps

# Query processes
curl http://localhost:8000/api/v1/processes?is_running=true

# Health check
curl http://localhost:8000/api/v1/health
