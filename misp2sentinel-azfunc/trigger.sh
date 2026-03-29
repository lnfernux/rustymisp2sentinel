#!/usr/bin/env bash
# Manually trigger the sync-timer function for testing.
# Usage: bash trigger.sh
curl -v -X POST http://localhost:7071/admin/functions/sync-timer \
  -H "Content-Type: application/json" \
  -d "{}"