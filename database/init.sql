-- ============================================
-- Lemonade Toolkit Database Schema
-- PostgreSQL Database Initialization
-- ============================================

-- Create database (run as superuser)
-- CREATE DATABASE lemonade_toolkit;

-- Connect to the database
-- \c lemonade_toolkit;

-- ============================================
-- TABLES
-- ============================================

-- Payments table - Core payment tracking
CREATE TABLE IF NOT EXISTS payments (
    id SERIAL PRIMARY KEY,
    stripe_payment_id VARCHAR(255) UNIQUE NOT NULL,
    stripe_customer_id VARCHAR(255),
    email VARCHAR(255) NOT NULL,
    amount INTEGER NOT NULL,
    currency VARCHAR(10) NOT NULL,
    status VARCHAR(50) NOT NULL,
    access_token VARCHAR(255) UNIQUE,
    token_expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    accessed_count INTEGER DEFAULT 0,
    last_accessed_at TIMESTAMP,
    metadata JSONB,
    
    -- Indexes for performance
    INDEX idx_payments_email (email),
    INDEX idx_payments_status (status),
    INDEX idx_payments_access_token (access_token),
    INDEX idx_payments_created_at (created_at DESC)
);

-- Download logs - Track all downloads for security
CREATE TABLE IF NOT EXISTS download_logs (
    id SERIAL PRIMARY KEY,
    payment_id INTEGER REFERENCES payments(id) ON DELETE CASCADE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    downloaded_at TIMESTAMP DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_download_logs_payment_id (payment_id),
    INDEX idx_download_logs_downloaded_at (downloaded_at DESC)
);

-- Admin sessions - Secure admin access
CREATE TABLE IF NOT EXISTS admin_sessions (
    id SERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_activity TIMESTAMP DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_admin_sessions_token (token),
    INDEX idx_admin_sessions_expires_at (expires_at)
);

-- Failed login attempts - Security monitoring
CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    attempted_at TIMESTAMP DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_failed_login_ip (ip_address),
    INDEX idx_failed_login_attempted_at (attempted_at DESC)
);

-- Audit log - Track all important actions
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id INTEGER,
    user_type VARCHAR(20),
    user_id VARCHAR(255),
    ip_address VARCHAR(45),
    details JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_audit_log_action (action),
    INDEX idx_audit_log_created_at (created_at DESC)
);

-- Email queue - Async email processing
CREATE TABLE IF NOT EXISTS email_queue (
    id SERIAL PRIMARY KEY,
    to_email VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    html_content TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    attempts INTEGER DEFAULT 0,
    last_attempt_at TIMESTAMP,
    sent_at TIMESTAMP,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_email_queue_status (status),
    INDEX idx_email_queue_created_at (created_at)
);

-- ============================================
-- VIEWS
-- ============================================

-- Sales statistics view
CREATE OR REPLACE VIEW sales_statistics AS
SELECT 
    COUNT(*) as total_sales,
    COUNT(DISTINCT email) as unique_customers,
    SUM(amount) / 100.0 as total_revenue_dollars,
    AVG(amount) / 100.0 as average_sale_dollars,
    MAX(created_at) as last_sale_date,
    COUNT(CASE WHEN created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as sales_last_24h,
    COUNT(CASE WHEN created_at > NOW() - INTERVAL '7 days' THEN 1 END) as sales_last_7d,
    COUNT(CASE WHEN created_at > NOW() - INTERVAL '30 days' THEN 1 END) as sales_last_30d,
    COUNT(CASE WHEN accessed_count > 0 THEN 1 END) as customers_who_downloaded,
    AVG(accessed_count) as avg_downloads_per_customer
FROM payments
WHERE status = 'completed';

-- Active sessions view
CREATE OR REPLACE VIEW active_admin_sessions AS
SELECT 
    id,
    token,
    ip_address,
    expires_at,
    created_at,
    last_activity,
    CASE 
        WHEN expires_at > NOW() THEN 'active'
        ELSE 'expired'
    END as status
FROM admin_sessions
WHERE expires_at > NOW() - INTERVAL '24 hours'
ORDER BY created_at DESC;

-- Recent security events view
CREATE OR REPLACE VIEW security_events AS
SELECT 
    'failed_login' as event_type,
    attempted_at as event_time,
    ip_address,
    username as details
FROM failed_login_attempts
WHERE attempted_at > NOW() - INTERVAL '24 hours'
UNION ALL
SELECT 
    'admin_login' as event_type,
    created_at as event_time,
    ip_address,
    'Admin session created' as details
FROM admin_sessions
WHERE created_at > NOW() - INTERVAL '24 hours'
ORDER BY event_time DESC;

-- ============================================
-- FUNCTIONS
-- ============================================

-- Function to clean up expired tokens
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM admin_sessions WHERE expires_at < NOW() - INTERVAL '7 days';
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    DELETE FROM payments 
    WHERE token_expires_at < NOW() - INTERVAL '30 days' 
    AND accessed_count = 0;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to check for suspicious activity
CREATE OR REPLACE FUNCTION check_suspicious_activity(check_ip VARCHAR(45))
RETURNS TABLE(
    is_suspicious BOOLEAN,
    failed_attempts_count INTEGER,
    last_attempt TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*) >= 5 as is_suspicious,
        COUNT(*)::INTEGER as failed_attempts_count,
        MAX(attempted_at) as last_attempt
    FROM failed_login_attempts
    WHERE ip_address = check_ip
    AND attempted_at > NOW() - INTERVAL '15 minutes';
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- TRIGGERS
-- ============================================

-- Trigger to log payment changes
CREATE OR REPLACE FUNCTION log_payment_changes()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (action, entity_type, entity_id, details)
    VALUES (
        TG_OP,
        'payment',
        NEW.id,
        jsonb_build_object(
            'email', NEW.email,
            'amount', NEW.amount,
            'status', NEW.status,
            'old_status', OLD.status
        )
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER payment_audit_trigger
AFTER INSERT OR UPDATE ON payments
FOR EACH ROW
EXECUTE FUNCTION log_payment_changes();

-- ============================================
-- INITIAL DATA
-- ============================================

-- Insert initial audit log entry
INSERT INTO audit_log (action, entity_type, details)
VALUES ('DATABASE_INITIALIZED', 'system', '{"version": "1.0.0", "timestamp": NOW()}');

-- ============================================
-- PERMISSIONS (Adjust based on your database users)
-- ============================================

-- Create read-only user for reporting (optional)
-- CREATE USER lemonade_readonly WITH PASSWORD 'secure_password';
-- GRANT CONNECT ON DATABASE lemonade_toolkit TO lemonade_readonly;
-- GRANT USAGE ON SCHEMA public TO lemonade_readonly;
-- GRANT SELECT ON ALL TABLES IN SCHEMA public TO lemonade_readonly;

-- Create application user with appropriate permissions
-- CREATE USER lemonade_app WITH PASSWORD 'secure_password';
-- GRANT CONNECT ON DATABASE lemonade_toolkit TO lemonade_app;
-- GRANT USAGE ON SCHEMA public TO lemonade_app;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO lemonade_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO lemonade_app;

-- ============================================
-- MAINTENANCE QUERIES
-- ============================================

-- Query to run periodically to clean up old data
-- DELETE FROM download_logs WHERE downloaded_at < NOW() - INTERVAL '90 days';
-- DELETE FROM failed_login_attempts WHERE attempted_at < NOW() - INTERVAL '30 days';
-- DELETE FROM audit_log WHERE created_at < NOW() - INTERVAL '180 days';
-- SELECT cleanup_expired_tokens();

-- ============================================
-- USEFUL QUERIES FOR MONITORING
-- ============================================

/*
-- Check recent payments
SELECT email, amount/100.0 as dollars, status, created_at 
FROM payments 
ORDER BY created_at DESC 
LIMIT 10;

-- Check suspicious IPs
SELECT ip_address, COUNT(*) as attempts 
FROM failed_login_attempts 
WHERE attempted_at > NOW() - INTERVAL '1 hour' 
GROUP BY ip_address 
HAVING COUNT(*) > 3;

-- Check download patterns
SELECT p.email, COUNT(d.id) as download_count, MAX(d.downloaded_at) as last_download
FROM payments p
JOIN download_logs d ON p.id = d.payment_id
GROUP BY p.email
ORDER BY download_count DESC;

-- Revenue by day
SELECT DATE(created_at) as date, COUNT(*) as sales, SUM(amount)/100.0 as revenue
FROM payments
WHERE status = 'completed'
GROUP BY DATE(created_at)
ORDER BY date DESC
LIMIT 30;
*/