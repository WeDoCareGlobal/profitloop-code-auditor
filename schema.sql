-- ProfitLoop Code Auditor Schema
-- Tables: audit_jobs, audit_findings, audit_reports, vulnerability_db

CREATE TABLE IF NOT EXISTS audit_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_url TEXT NOT NULL,
  commit_hash TEXT,
  language TEXT, -- 'solidity', 'rust', 'go', 'typescript', 'python'
  audit_type TEXT DEFAULT 'full', -- 'full', 'security', 'gas', 'logic', 'dependencies'
  status TEXT DEFAULT 'queued', -- 'queued', 'running', 'completed', 'failed'
  severity_threshold TEXT DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
  findings_count INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  started_at DATETIME,
  completed_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL,
  file_path TEXT NOT NULL,
  line_start INTEGER,
  line_end INTEGER,
  severity TEXT NOT NULL, -- 'critical', 'high', 'medium', 'low', 'info'
  category TEXT, -- 'reentrancy', 'overflow', 'access_control', 'logic_error', 'gas_optimization'
  title TEXT NOT NULL,
  description TEXT,
  recommendation TEXT,
  code_snippet TEXT,
  cwe_id TEXT,
  confidence REAL DEFAULT 0.8,
  false_positive BOOLEAN DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (job_id) REFERENCES audit_jobs(id)
);

CREATE TABLE IF NOT EXISTS audit_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL UNIQUE,
  summary TEXT,
  executive_summary TEXT,
  risk_score REAL, -- 0-100
  passed BOOLEAN,
  report_format TEXT DEFAULT 'markdown', -- 'markdown', 'json', 'pdf', 'sarif'
  report_path TEXT, -- KV/R2 path
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (job_id) REFERENCES audit_jobs(id)
);

CREATE TABLE IF NOT EXISTS vulnerability_db (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL, -- regex or AST pattern
  language TEXT NOT NULL,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT,
  fix_template TEXT,
  "references" TEXT, -- JSON array of URLs (quoted: reserved word)
  enabled INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON audit_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_repo ON audit_jobs(repo_url);
CREATE INDEX IF NOT EXISTS idx_findings_job ON audit_findings(job_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON audit_findings(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_lang ON vulnerability_db(language);

INSERT OR IGNORE INTO vulnerability_db (pattern, language, severity, category, description, fix_template) VALUES
('\\.call\\{value:', 'solidity', 'critical', 'reentrancy', 'Unchecked external call with value transfer', 'Use reentrancy guard, check-effects-interactions pattern'),
('tx\\.origin', 'solidity', 'high', 'access_control', 'Using tx.origin for authorization', 'Use msg.sender instead'),
('\\.transfer\\(', 'solidity', 'medium', 'gas_optimization', 'transfer() forwards only 2300 gas', 'Use .call{value:} with proper error handling'),
('unchecked\\s*\\{', 'solidity', 'low', 'overflow', 'Unchecked arithmetic block', 'Add overflow checks or use SafeMath'),
('eval\\(', 'javascript', 'critical', 'injection', 'Use of eval()', 'Avoid eval, use safe parsing'),
('innerHTML\\s*=', 'javascript', 'high', 'xss', 'Direct innerHTML assignment', 'Use textContent or sanitize HTML');