# Skyhook API Reference

Last updated: 2026-06-13

## Overview

Skyhook exposes a REST API for control and monitoring. The API is available at `http://localhost:9999` by default.

## Authentication

Currently, the API does not require authentication. In production deployments, it is recommended to:

1. Bind to localhost only.
2. Use a reverse proxy with authentication.
3. Use firewall rules to restrict access.

## Endpoints

### Health Check

```
GET /health
```

Response:
```json
{
  "ok": true
}
```

### Version

```
GET /version
```

Response:
```json
{
  "name": "Skyhook",
  "version": "0.1.0",
  "engine": "rust-native"
}
```

### Status

```
GET /status
```

Response:
```json
{
  "ok": true,
  "running": true,
  "uptime_secs": 3600,
  "connections": 42,
  "memory_mb": 128
}
```

### Configuration

```
GET /config
```

Response:
```json
{
  "ok": true,
  "config": {
    "core": { ... },
    "tun": { ... },
    "dns": { ... },
    "smart_rules": { ... },
    "subscriptions": { ... },
    "outbounds": [ ... ],
    "rules": [ ... ]
  }
}
```

### Reload Configuration

```
POST /config/reload
```

Request:
```json
{
  "config": { ... }
}
```

Response:
```json
{
  "ok": true,
  "runtime": {
    "reloaded": true,
    "summary": "...",
    "default_outbound": "direct"
  }
}
```

### Outbounds

```
GET /outbounds
```

Response:
```json
{
  "ok": true,
  "outbounds": [
    {
      "name": "direct",
      "kind": "direct",
      "tcp_supported": true,
      "udp_supported": true
    }
  ]
}
```

### Probe Outbounds

```
POST /outbounds/probe
```

Response:
```json
{
  "ok": true,
  "results": [
    {
      "name": "proxy-1",
      "kind": "shadowsocks",
      "success": true,
      "latency_ms": 150
    }
  ]
}
```

### Proxy Groups

```
GET /groups
```

Response:
```json
{
  "ok": true,
  "groups": [
    {
      "name": "auto",
      "kind": "url-test",
      "members": [ ... ]
    }
  ]
}
```

### Country Groups

```
GET /countries
```

Response:
```json
{
  "ok": true,
  "countries": [
    {
      "code": "US",
      "name": "United States",
      "node_count": 5
    }
  ]
}
```

### Subscriptions

```
GET /subscriptions
```

Response:
```json
{
  "ok": true,
  "subscriptions": [
    {
      "id": "sub-1",
      "name": "My Subscription",
      "url": "https://...",
      "active": true,
      "last_updated_at": "2026-06-13T00:00:00Z"
    }
  ]
}
```

### Import Subscription

```
POST /subscriptions/import
```

Request:
```json
{
  "url": "https://..."
}
```

Response:
```json
{
  "ok": true,
  "subscription": {
    "id": "sub-2",
    "name": "New Subscription"
  }
}
```

### Update All Subscriptions

```
POST /subscriptions/update-all
```

Response:
```json
{
  "ok": true,
  "results": [
    {
      "id": "sub-1",
      "name": "My Subscription",
      "updated": true,
      "error": null
    }
  ]
}
```

### Background Tasks

```
GET /skyhook/tasks
```

Response:
```json
{
  "ok": true,
  "tasks": [
    {
      "name": "subscription_update",
      "interval_secs": 3600,
      "enabled": true,
      "running": false,
      "last_run_at": "2026-06-13T00:00:00Z",
      "run_count": 10,
      "success_count": 9,
      "failure_count": 1
    }
  ]
}
```

### Run Task Now

```
POST /skyhook/tasks/run-now
```

Request:
```json
{
  "name": "subscription_update"
}
```

Response:
```json
{
  "ok": true,
  "message": "task 'subscription_update' triggered"
}
```

### Pause Task

```
POST /skyhook/tasks/pause
```

Request:
```json
{
  "name": "subscription_update"
}
```

Response:
```json
{
  "ok": true,
  "message": "task 'subscription_update' paused"
}
```

### Resume Task

```
POST /skyhook/tasks/resume
```

Request:
```json
{
  "name": "subscription_update"
}
```

Response:
```json
{
  "ok": true,
  "message": "task 'subscription_update' resumed"
}
```

### Smart Rules Stats

```
GET /skyhook/smart-rules/stats
```

Response:
```json
{
  "ok": true,
  "stats": {
    "observed_targets": 100,
    "total_visits": 1000,
    "direct_probe_attempts": 50,
    "direct_probe_successes": 45,
    "direct_probe_success_ratio": 0.9
  }
}
```

### Smart Rules Observations

```
GET /skyhook/smart-rules/observations
```

Response:
```json
{
  "ok": true,
  "observations": [
    {
      "key": "domain:example.com",
      "target": "domain",
      "value": "example.com",
      "visits": 10,
      "direct_probe_successes": 8,
      "recommendation_state": "pending"
    }
  ]
}
```

### Smart Rules Recommendations

```
GET /skyhook/smart-rules/recommendations
```

Response:
```json
{
  "ok": true,
  "recommendations": {
    "direct": [
      {
        "target": "domain",
        "value": "example.com",
        "recommended_outbound": "direct",
        "action": "direct",
        "confidence": 0.9,
        "reason": "direct probe successful"
      }
    ],
    "proxy": [ ... ]
  }
}
```

### Apply Recommendation

```
POST /skyhook/smart-rules/recommendations/apply-one
```

Request:
```json
{
  "target": "domain",
  "value": "example.com"
}
```

Response:
```json
{
  "ok": true,
  "message": "recommendation applied"
}
```

### Apply All Recommendations

```
POST /skyhook/smart-rules/recommendations/apply-all
```

Response:
```json
{
  "ok": true,
  "applied": 10,
  "message": "10 recommendations applied"
}
```

### Ignore Recommendation

```
POST /skyhook/smart-rules/recommendations/ignore
```

Request:
```json
{
  "target": "domain",
  "value": "example.com"
}
```

Response:
```json
{
  "ok": true,
  "message": "recommendation ignored"
}
```

### Undo Smart Rule

```
POST /skyhook/smart-rules/undo
```

Request:
```json
{
  "target": "domain",
  "value": "example.com"
}
```

Response:
```json
{
  "ok": true,
  "message": "smart rule undone"
}
```

### Traffic Summary

```
GET /traffic/summary
```

Response:
```json
{
  "ok": true,
  "traffic": {
    "global_upload": 1000000,
    "global_download": 5000000,
    "per_outbound": { ... },
    "per_subscription": { ... },
    "per_domain": { ... },
    "per_app": { ... },
    "per_protocol": { ... }
  }
}
```

### Logs

```
GET /logs
```

Response:
```json
{
  "ok": true,
  "logs": [
    {
      "level": "info",
      "message": "Server started",
      "timestamp": "2026-06-13T00:00:00Z"
    }
  ]
}
```

### Smart Rules

```
GET /skyhook/rules
```

Response:
```json
{
  "ok": true,
  "rules": [
    {
      "target": "domain",
      "value": "example.com",
      "outbound": "direct",
      "enabled": true
    }
  ]
}
```

### Add Smart Rule

```
POST /skyhook/rules
```

Request:
```json
{
  "target": "domain",
  "value": "example.com",
  "outbound": "direct"
}
```

Response:
```json
{
  "ok": true,
  "rule": {
    "target": "domain",
    "value": "example.com",
    "outbound": "direct",
    "enabled": true
  }
}
```

### Delete Smart Rule

```
POST /skyhook/rules/delete
```

Request:
```json
{
  "target": "domain",
  "value": "example.com"
}
```

Response:
```json
{
  "ok": true,
  "message": "rule deleted"
}
```

## Error Responses

All endpoints return errors in the following format:

```json
{
  "ok": false,
  "error": "Error message"
}
```

## CLI Commands

Skyhook supports the following CLI commands:

```bash
# Check configuration
skyhook check -c skyhook.yaml

# Run proxy
skyhook run -c skyhook.yaml

# Probe all outbounds
skyhook probe --all

# Import subscription
skyhook subscriptions import --url https://...

# Update all subscriptions
skyhook subscriptions update-all

# Show traffic summary
skyhook traffic summary

# Show smart rules stats
skyhook smart stats

# Test native TUN
skyhook native-tun test

# Run benchmarks
skyhook bench
```
