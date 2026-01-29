-- Add google_id for Google Sign-In (Unique)
ALTER TABLE users ADD COLUMN google_id VARCHAR(255) UNIQUE;

-- Make password_hash nullable (Google users won't have one)
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- Add expiry for verification tokens (OTP support)
ALTER TABLE users ADD COLUMN verification_token_expires TIMESTAMPTZ;
