CREATE DATABASE IF NOT EXISTS phishshield
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE phishshield;

-- Core tables, analytics, threat feed, and badges are defined below.

CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(60) NOT NULL,
  email VARCHAR(254) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  email_verified TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS email_verified TINYINT(1) NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS login_activity (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  email VARCHAR(254) NOT NULL,
  logged_in_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_login_activity_user_time (user_id, logged_in_at),
  CONSTRAINT fk_login_activity_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS scan_history (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  scan_type ENUM('email', 'website', 'message', 'qr') NOT NULL,
  content MEDIUMTEXT NOT NULL,
  status ENUM('safe', 'caution', 'phishing') NOT NULL,
  score INT NOT NULL,
  percentage TINYINT UNSIGNED NOT NULL DEFAULT 0,
  confidence TINYINT UNSIGNED NOT NULL DEFAULT 0,
  flags JSON NULL,
  urls JSON NULL,
  explanation JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_scans_user_created (user_id, created_at),
  CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB;

ALTER TABLE scan_history
  MODIFY COLUMN scan_type ENUM('email', 'website', 'message', 'qr') NOT NULL,
  MODIFY COLUMN flags JSON NULL,
  MODIFY COLUMN urls JSON NULL,
  ADD COLUMN IF NOT EXISTS percentage TINYINT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS confidence TINYINT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS explanation JSON NULL;

CREATE TABLE IF NOT EXISTS threat_blocklist (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  domain VARCHAR(255) NOT NULL,
  reason VARCHAR(255) NOT NULL,
  reported_by BIGINT UNSIGNED NULL,
  votes INT NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_threat_blocklist_domain (domain),
  KEY idx_threat_blocklist_votes (votes),
  CONSTRAINT fk_threat_reporter FOREIGN KEY (reported_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS rate_limits (
  user_id BIGINT UNSIGNED NOT NULL,
  window_start TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  count INT NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id),
  CONSTRAINT fk_rate_limits_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS scan_analytics (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NULL,
  scan_type ENUM('email', 'website', 'message', 'qr', 'bulk') NOT NULL,
  host VARCHAR(255) NOT NULL,
  tld VARCHAR(64) NOT NULL,
  verdict ENUM('safe', 'caution', 'phishing') NOT NULL,
  score INT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_scan_analytics_created_at (created_at),
  KEY idx_scan_analytics_tld (tld)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS threat_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  domain VARCHAR(255) NOT NULL,
  reason VARCHAR(255) NOT NULL,
  score INT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_threat_events_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS badges (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  badge_key VARCHAR(100) NOT NULL,
  awarded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_badges_user_badge (user_id, badge_key),
  CONSTRAINT fk_badges_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
