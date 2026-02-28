#!/bin/sh
set -e

# Run DB migrations before starting the server
dns-orchestrator --migrate

exec "$@"
