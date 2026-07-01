-- Database Schema for RightDone Intelligence OSINT App

CREATE TABLE IF NOT EXISTS reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(128) NOT NULL,
    pricing_level ENUM('free', 'surcharge1', 'surcharge2') NOT NULL,
    target_type ENUM('ico', 'domain', 'company', 'person', 'ip') NOT NULL,
    target_value VARCHAR(255) NOT NULL,
    raw_data LONGTEXT, -- Stores the JSON payload of the raw data fetched
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_session_id (session_id),
    INDEX idx_target (target_type, target_value)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS entities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    type ENUM('company', 'person', 'domain', 'ip', 'certificate', 'email', 'phone', 'address') NOT NULL,
    value VARCHAR(255) NOT NULL,
    risk_level ENUM('informational', 'low', 'medium', 'high', 'critical') NOT NULL,
    description TEXT,
    payload JSON, -- Extra structured properties
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY idx_type_value (type, value),
    INDEX idx_risk_level (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS report_entities (
    report_id INT NOT NULL,
    entity_id INT NOT NULL,
    PRIMARY KEY (report_id, entity_id),
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE,
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
    INDEX idx_report_id (report_id),
    INDEX idx_entity_id (entity_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS relations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    entity_from_id INT NOT NULL,
    entity_to_id INT NOT NULL,
    relation_type VARCHAR(50) NOT NULL, -- e.g., 'owner', 'director', 'dns_record', 'ssl_cert'
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_from_id) REFERENCES entities(id) ON DELETE CASCADE,
    FOREIGN KEY (entity_to_id) REFERENCES entities(id) ON DELETE CASCADE,
    INDEX idx_from (entity_from_id),
    INDEX idx_to (entity_to_id),
    INDEX idx_relation_type (relation_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(128) NOT NULL,
    action VARCHAR(255) NOT NULL, -- e.g., 'search', 'pdf_download', 'payment'
    target_type VARCHAR(50),
    target_value VARCHAR(255),
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_session (session_id),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;