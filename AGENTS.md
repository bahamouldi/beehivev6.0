# AGENTS.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

BeeWAF is a production-ready Web Application Firewall built with FastAPI and scikit-learn. It provides multi-layer protection including 2500+ regex rules, ML-based anomaly detection (IsolationForest + ensemble), and 27 enterprise security modules. Documentation is in French.

## Build and Run Commands

### Local Development
```bash
# Create virtual environment and install dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run the development server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Docker
```bash
# Build image
docker build -t beewaf:sklearn .

# Run with ELK stack (recommended)
docker-compose -f docker-compose-elk.yaml up -d

# Run minimal stack (WAF + Nginx only)
docker-compose up -d
```

### Testing
```bash
# Unit tests with pytest
pytest -v

# Run specific test file
pytest tests/test_admin_rules.py -v

# Integration tests (requires running container)
./tests/test_waf.sh

# Manual attack tests
python tests/run_tests.py
```

### Kubernetes Deployment
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
```

## Architecture

### Core Components

- **`app/main.py`**: FastAPI application with WAF middleware. All HTTP requests pass through `waf_middleware()` which orchestrates detection modules. Supports reverse proxy mode when `BACKEND_URL` is set.

- **`waf/`**: Security module package containing:
  - `rules.py`, `rules_extended.py`, `rules_advanced.py`, `rules_v5.py`: Regex pattern databases for attack detection (SQLi, XSS, Command Injection, Path Traversal, SSRF, XXE, LDAP Injection, etc.)
  - `rules_mega_*.py` (1-12): Additional specialized rule sets
  - `anomaly.py`: Legacy IsolationForest ML model
  - `ml_engine.py`: Advanced 3-model ensemble (IsolationForest + RandomForest + GradientBoosting)
  - Enterprise modules: `bot_detector.py`, `dlp.py`, `geo_block.py`, `protocol_validator.py`, `api_security.py`, `threat_intel.py`, `session_protection.py`, `ddos_protection.py`, etc.

### Request Flow

1. Request enters `waf_middleware()` in `app/main.py`
2. IP blocklist check → Rate limiting check
3. Path normalization and validation
4. Header validation (Host, X-Forwarded-For, Transfer-Encoding)
5. Business logic abuse checks
6. Enterprise WAF modules (protocol, bot, DLP, geo, API security, etc.)
7. Regex rules matching via `waf.rules.match_payload()`
8. ML anomaly detection via `waf.anomaly` and `waf.ml_engine`
9. Clean requests forwarded to backend or served locally

### Data and Models

- **`data/`**: Training datasets (`csic_database.csv`, `train_synthetic.csv`, `train_kaggle.csv`)
- **`models/`**: Serialized ML models (`model.pkl` for legacy, `ml_engine.pkl` for ensemble)

## Environment Variables

Key configuration options:
- `BACKEND_URL`: Backend application URL (reverse proxy mode)
- `BEEWAF_API_KEY`: API key for admin endpoints
- `BEEWAF_MODEL_PATH`: Path to legacy ML model (default: `models/model.pkl`)
- `BEEWAF_ML_ENGINE_PATH`: Path to ensemble model (default: `models/ml_engine.pkl`)
- `BEEWAF_ML_MODE`: `legacy` or `advanced` (default: `advanced`)
- `BEEWAF_RATE_LIMIT_MAX`: Rate limit requests per window
- `BEEWAF_ALLOWED_HOSTS`: Comma-separated list of allowed Host headers

## Key Patterns

### Adding New Detection Rules

Add regex patterns to the appropriate category list in `waf/rules.py`:
```python
SQLI_PATTERNS = [
    # existing patterns...
    r"your_new_pattern_here",
]
```

### Testing Attack Detection

```bash
# SQL Injection
curl -X POST http://localhost:8000/echo -d "' OR 1=1--"

# XSS
curl -X POST http://localhost:8000/echo -d "<script>alert(1)</script>"

# Expected response for blocked requests:
# {"blocked": true, "reason": "regex-sqli"}
```

### Admin Endpoints

Protected by `X-API-Key` header:
- `GET /admin/rules` - List all WAF rules
- `POST /admin/retrain` - Retrain ML model
