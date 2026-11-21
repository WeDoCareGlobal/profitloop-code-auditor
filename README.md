# ProfitLoop Code Auditor

Security audit engine for AI-generated code with severity-classified findings and audit reports. Detects reentrancy, overflow, access control, logic errors, and gas optimization issues across Solidity, Rust, Go, TypeScript, and Python.

## 🚀 Quick Start

Deploy to Cloudflare Workers in 5 minutes:

```bash
# Install Wrangler
npm install -g wrangler

# Login to Cloudflare
wrangler login

# Configure secrets
wrangler secret put STRIPE_SECRET_KEY

# Deploy
wrangler deploy
```

## 📋 API Endpoints

- GET /api/health - Service health check
- GET /api/stats - Audit statistics
- GET /api/ledger - Full audit ledger
- GET /api/:resource - Read resource (audit_jobs, audit_findings, audit_reports)
- POST /api/:resource - Create resource
- POST /api/act/audit - Run security audit on repository
- POST /api/act/verify - Verify audit findings

## ✨ Features

- Severity-classified findings (critical, high, medium, low, info)
- Multi-language support: Solidity, Rust, Go, TypeScript, Python
- CWE ID mapping for each finding
- Audit reports with confidence scoring
- False-positive flagging
- Cloudflare Workers AI + D1 Database

## 🎯 Best For

Teams shipping AI-generated code who need automated security audits before deployment.

## 💰 Pricing

**$29/month** per seat

## 🔧 Required Cloudflare Resources

- Workers AI (Llama 3.1 8B)
- D1 database (`pharma-intelligence-db`)
- KV namespace (`CACHE`)

## 📊 Schema Tables

audit_jobs, audit_findings, audit_reports, vulnerability_db

---

## 📄 License

Apache License 2.0

## 🔗 Links

- [WeDoCare Global](https://wedocare-global.com)
- [Store](https://store.wedocare-global.com)

---
*Founded by Emir Perla · Sarajevo, Bosnia and Herzegovina · ORCID 0009-0009-8515-2727*
