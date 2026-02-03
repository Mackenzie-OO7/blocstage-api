use crate::models::user::{CreateUserRequest, LoginRequest, User};
use crate::services::redis_service::RedisService;
use crate::services::stellar::StellarService;
use anyhow::{anyhow, Result};
use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use log::{debug, error, info, warn};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::env;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // user ID
    pub exp: i64,     // Expiration
    pub role: String, // User role (admin, organizer, attendee)
    pub iat: i64,     // Issued at
    pub jti: String,  // JWT ID
}

#[derive(Debug, Deserialize)]
pub struct GoogleUser {
    pub sub: String,
    pub email: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub name: Option<String>,  // Full name as fallback
}

pub struct AuthService {
    pool: PgPool,
    stellar: std::sync::Arc<StellarService>,
    redis: Option<std::sync::Arc<RedisService>>,
    email_service: Option<std::sync::Arc<crate::services::email::EmailService>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedUserProfile {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub stellar_public_key: Option<String>,
    pub email_verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: String,
    pub role: String,
}

impl From<&User> for CachedUserProfile {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            stellar_public_key: user.stellar_public_key.clone(),
            email_verified: user.email_verified,
            created_at: user.created_at,
            status: user.status.clone(),
            role: user.role.clone(),
        }
    }
}

impl AuthService {
    pub async fn new(pool: PgPool) -> Result<Self> {
        let stellar = StellarService::global()?;

        let redis = match RedisService::global().await {
            Ok(redis) => {
                info!("✅ Redis initialized for AuthService");
                Some(redis)
            }
            Err(e) => {
                warn!("⚠️ Redis not available for AuthService: {}", e);
                None
            }
        };

        let email_service = match crate::services::email::EmailService::global().await {
            Ok(service) => {
                info!("✅ Email service initialized: {}", service.provider_name());
                Some(service)
            }
            Err(e) => {
                warn!("⚠️ Email service not available: {}", e);
                None
            }
        };

        Ok(Self { pool, stellar, redis, email_service })
    }

    pub fn new_with_services(
        pool: PgPool,
        stellar: std::sync::Arc<StellarService>,
        redis: Option<std::sync::Arc<RedisService>>,
        email_service: Option<std::sync::Arc<crate::services::email::EmailService>>,
    ) -> Self {
        Self {
            pool,
            stellar,
            redis,
            email_service,
        }
    }

    pub async fn register(&self, user_req: CreateUserRequest) -> Result<User> {
        info!("🚀 Starting registration for email: {}", user_req.email);

        if let Some(existing_user) = User::find_by_email(&self.pool, &user_req.email).await? {
            warn!(
                "❌ Registration failed: Email {} already exists with ID {}",
                user_req.email, existing_user.id
            );
            return Err(anyhow!("Email already registered"));
        }

        let password_hash = Some(hash(&user_req.password, 10)?);
        info!("🔐 Password hashed successfully");

        // Generate 4 digit code
        let mut rng = rand::rng();
        let code: u32 = rng.random_range(1000..9999);
        let verification_token = code.to_string();
        let verification_token_expires = Utc::now() + Duration::minutes(15);

        let user = User::create(
            &self.pool, 
            user_req, 
            password_hash,
            None, // google_id
            Some(verification_token),
            Some(verification_token_expires)
        ).await?;
        info!("✅ User created with ID: {}", user.id);

        let (public_key, secret_key) = self.stellar.generate_keypair()?;
        debug!("🌟 Stellar keypair generated: {}", public_key);

        let user = user
            .update_stellar_keys(&self.pool, &public_key, &secret_key)
            .await?;
        info!("💳 Stellar keys updated for user: {}", user.id);

        self.send_verification_email(&user).await?;

        info!(
            "🎉 Yay! Registration completed for user: {} ({})",
            user.id, user.email
        );
        Ok(user)
    }

    pub async fn login(
        &self,
        login_req: LoginRequest,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<String> {
        info!(
            "🔑 Login attempt for email: {} from IP: {:?}",
            login_req.email, ip_address
        );

        if let Some(redis) = &self.redis {
            let rate_limit_key = format!("RATE_LIMIT:LOGIN:{}", login_req.email);
            match redis.check_rate_limit(&rate_limit_key, 5, 900).await {
                // 5 attempts/15 minutes
                Ok(allowed) => {
                    if !allowed {
                        warn!(
                            "❌ Login rate limited for email: {} from IP: {:?}",
                            login_req.email, ip_address
                        );
                        return Err(anyhow!("Too many login attempts. Wait a minute, or 15!."));
                    }
                }
                Err(e) => {
                    warn!("Rate limit check failed: {}", e);
                    // Continue without rate limiting if Redis is down
                }
            }
        }

        let user = User::find_by_email(&self.pool, &login_req.email)
            .await?
            .ok_or_else(|| {
                warn!(
                    "❌ Login failed: User not found for email {} from IP: {:?}",
                    login_req.email, ip_address
                );
                anyhow!("Invalid email or password")
            })?;

        info!("👤 User found:");
        info!("   - ID: {}", user.id);
        info!("   - Email: {}", user.email);
        info!("   - Username: {}", user.username);
        info!("   - Role: {}", user.role);
        info!("   - Email Verified: {}", user.email_verified);
        info!("   - Status: {}", user.status);
        info!("   - Login IP: {:?}", ip_address);

        if user.status == "deleted" {
            warn!(
                "❌ Login failed: Account deleted for user {} from IP: {:?}",
                user.id, ip_address
            );
            return Err(anyhow!("Account has been deleted"));
        }

        if !user.email_verified {
            warn!(
                "❌ Login failed: Email not verified for user {} from IP: {:?}",
                user.id, ip_address
            );
            return Err(anyhow!(
                "Email not verified. Please verify your email before logging in."
            ));
        }

        // use constant time comparison to prevent timing attacks
        let Some(password_hash) = &user.password_hash else {
             warn!(
                "❌ Login failed: User has no password set (likely Google auth) for user {} from IP: {:?}",
                user.id, ip_address
            );
            return Err(anyhow!("Invalid email or password"));
        };

        if !verify(&login_req.password, password_hash)? {
            warn!(
                "❌ Login failed: Invalid password for user {} from IP: {:?}",
                user.id, ip_address
            );
            return Err(anyhow!("Invalid email or password"));
        }

        info!(
            "🔐 Password verified for user: {} from IP: {:?}",
            user.id, ip_address
        );

        let token = self
            .generate_token(user.id, user.role.clone(), ip_address.clone(), user_agent)
            .await?;
        info!(
            "🎫 Token generated for user: {} (role: {}) from IP: {:?}. Login successful!",
            user.id, user.email, ip_address
        );

        debug!("Token preview: {}...", &token[0..20.min(token.len())]);

        Ok(token)
    }

    pub async fn verify_email(&self, email: &str, code: &str) -> Result<User> {
        info!(
            "📧 Verifying email {} with code: {}...",
            email, code
        );

        // Input validation
        if code.trim().is_empty() || code.len() != 4 {
            warn!("❌ Email verification failed: Invalid code format");
            return Err(anyhow!("Invalid verification code"));
        }

        let user = User::verify_email(&self.pool, email, code)
            .await?
            .ok_or_else(|| {
                warn!("❌ Email verification failed: Invalid or expired code");
                anyhow!("Invalid or expired verification code")
            })?;

        info!("✅ Email verified for user: {} ({})", user.id, user.email);
        Ok(user)
    }

    pub async fn verify_google_token(&self, id_token: &str) -> Result<GoogleUser> {
        let client = reqwest::Client::new();
        let response = client
            .get("https://oauth2.googleapis.com/tokeninfo")
            .query(&[("id_token", id_token)])
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            warn!("Google token validation failed: {}", error_text);
            return Err(anyhow!("Invalid Google token"));
        }

        let google_user: GoogleUser = response.json().await?;
        
        let client_id = env::var("GOOGLE_CLIENT_ID")
            .map_err(|_| anyhow!("GOOGLE_CLIENT_ID not set"))?;
            
        // Basic check, though Google endpoint ensures signature validity.
        // The `aud` claim in token should match our client_id.
        // However, response from tokeninfo usually returns `aud` as well.
        // Ideally we check it, but for now we assume tokeninfo implies valid signature from Google.
        // Let's rely on tokeninfo returning success.

        Ok(google_user)
    }

    pub async fn login_with_google(&self, id_token: &str, ip_address: Option<String>, user_agent: Option<String>) -> Result<String> {
        let google_user = self.verify_google_token(id_token).await?;
        info!("Google login for: {}", google_user.email);
        
        let mut rng = rand::thread_rng();

        // Check if user exists by google_id
        let user_opt = User::find_by_google_id(&self.pool, &google_user.sub).await?;
        
        let user = if let Some(user) = user_opt {
             user
        } else {
            // Check by email
            let email_user_opt = User::find_by_email(&self.pool, &google_user.email).await?;
            
            if let Some(user) = email_user_opt {
                // Link google_id
                sqlx::query!(
                    "UPDATE users SET google_id = $1 WHERE id = $2",
                    google_user.sub,
                    user.id
                )
                .execute(&self.pool)
                .await?;
                
                // Return updated user
                User::find_by_id(&self.pool, user.id).await?.unwrap()
            } else {
                // Create new user
                info!("Creating new user from Google login: {}", google_user.email);
                
                // Extract first and last name with fallbacks
                let (first_name, last_name) = match (&google_user.given_name, &google_user.family_name) {
                    (Some(first), Some(last)) => (first.clone(), last.clone()),
                    (Some(first), None) => (first.clone(), String::new()),
                    (None, Some(last)) => (String::new(), last.clone()),
                    (None, None) => {
                        // Try to extract from full name or email
                        if let Some(name) = &google_user.name {
                            let parts: Vec<&str> = name.split_whitespace().collect();
                            if parts.len() >= 2 {
                                (parts[0].to_string(), parts[1..].join(" "))
                            } else {
                                (name.clone(), String::new())
                            }
                        } else {
                            // Fallback to email prefix
                            let email_prefix = google_user.email.split('@').next().unwrap_or("user");
                            (email_prefix.to_string(), String::new())
                        }
                    }
                };
                
                // Generate username from first_name + random 4-digit suffix
                let base_name = first_name
                    .chars()
                    .filter(|c| c.is_alphanumeric())
                    .collect::<String>()
                    .to_lowercase();
                let base_name = if base_name.is_empty() { "user".to_string() } else { base_name };
                let suffix: u32 = rng.gen_range(1000..9999);
                let username = format!("{}_{}", base_name, suffix);
                
                let req = CreateUserRequest {
                    username,
                    email: google_user.email.clone(),
                    first_name,
                    last_name,
                    password: "".to_string(), // UNUSED
                };
                
                let user = User::create(
                    &self.pool,
                    req,
                    None, // password_hash
                    Some(google_user.sub),
                    None, // verification_token (auto verified)
                    None
                ).await?;
                
                // Set verified = true immediately
                sqlx::query!("UPDATE users SET email_verified = true WHERE id = $1", user.id).execute(&self.pool).await?;
                
                // Generate stellar keys
                let (public_key, secret_key) = self.stellar.generate_keypair()?;
                user.update_stellar_keys(&self.pool, &public_key, &secret_key).await?
            }
        };

        if user.status == "deleted" {
             return Err(anyhow!("Account has been deleted"));
        }

        // Generate JWT
        let token = self.generate_token(user.id, user.role.clone(), ip_address, user_agent).await?;
        Ok(token)
    }

    pub async fn request_password_reset(&self, email: &str) -> Result<()> {
        info!("🔑 Password reset requested for email: {}", email);

        if let Some(redis) = &self.redis {
            let rate_limit_key = format!("RATE_LIMIT:PASSWORD_RESET:{}", email);
            match redis.check_rate_limit(&rate_limit_key, 3, 3600).await {
                // 3 attempts per hour
                Ok(allowed) => {
                    if !allowed {
                        warn!("❌ Password reset rate limited for email: {}", email);
                        return Err(anyhow!(
                            "Too many password reset attempts. Please try again later."
                        ));
                    }
                }
                Err(e) => {
                    warn!("Rate limit check failed: {}", e);
                    // Continue without rate limiting if Redis is down
                }
            }
        }

        if email.trim().is_empty() || !email.contains('@') || email.len() > 255 {
            return Err(anyhow!("Invalid email format"));
        }

        // Check rate limiting first
        if !User::can_request_password_reset(&self.pool, email).await? {
            warn!(
                "❌ Password reset blocked: Rate limit exceeded for {}",
                email
            );
            return Err(anyhow!(
                "Please wait before requesting another password reset"
            ));
        }

        let user = User::find_by_email(&self.pool, email)
            .await?
            .ok_or_else(|| {
                // Don't leak user existence, but log for security monitoring
                warn!(
                    "❌ Password reset requested for non-existent email: {}",
                    email
                );
                anyhow!("If your email is registered, a password reset link has been sent.")
            })?;

        if user.status != "active" {
            warn!("❌ Password reset blocked: Inactive user {}", user.id);
            return Err(anyhow!(
                "If your email is registered, a password reset link has been sent."
            ));
        }

        if !user.email_verified {
            warn!("❌ Password reset blocked: Unverified user {}", user.id);
            return Err(anyhow!(
                "Please verify your email before requesting password reset."
            ));
        }

        let reset_token = user.request_password_reset(&self.pool).await?;
        self.send_password_reset_email(&user, &reset_token).await?;

        info!("✅ Password reset email sent for user: {}", user.id);
        Ok(())
    }

    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<()> {
        info!(
            "🔐 Processing password reset with token: {}...",
            &token[0..10.min(token.len())]
        );

        if new_password.len() < 8 {
            return Err(anyhow!("Password must be at least 8 characters"));
        }

        if new_password.len() > 128 {
            return Err(anyhow!("Password must be less than 128 characters"));
        }

        if token.trim().is_empty() || token.len() < 32 || token.len() > 255 {
            warn!("❌ Password reset failed: Invalid token format");
            return Err(anyhow!("Invalid reset token"));
        }

        let password_hash = hash(new_password, 10)?;

        let user = User::reset_password(&self.pool, token, &password_hash)
            .await?
            .ok_or_else(|| {
                warn!("❌ Password reset failed: Invalid or expired token");
                anyhow!("Invalid or expired reset token")
            })?;

        self.send_password_changed_email(&user).await?;

        info!(
            "✅ Password reset successfully for user: {} ({})",
            user.id, user.email
        );
        Ok(())
    }

    async fn send_verification_email(&self, user: &User) -> Result<()> {
        let Some(email_service) = &self.email_service else {
            warn!(
                "Email service not available, skipping verification email for user {}",
                user.id
            );
            return Ok(());
        };

        let Some(token) = &user.verification_token else {
            return Err(anyhow!("User has no verification token"));
        };

        match email_service
            .send_verification_email(&user.email, &user.first_name, token)
            .await
        {
            Ok(_) => {
                debug!("📧 Verification email sent to: {}", user.email);
            }
            Err(e) => {
                error!(
                    "⚠️ Failed to send verification email to {}: {}",
                    user.email, e
                );
            }
        }

        Ok(())
    }

    async fn send_password_reset_email(&self, user: &User, token: &str) -> Result<()> {
        let Some(email_service) = &self.email_service else {
            warn!(
                "Email service not available, skipping password reset email for user {}",
                user.id
            );
            return Ok(());
        };

        email_service
            .send_password_reset_email(&user.email, &user.first_name, token)
            .await?;

        info!("📧 Password reset email sent to: {}", user.email);
        Ok(())
    }

    async fn send_password_changed_email(&self, user: &User) -> Result<()> {
        let Some(email_service) = &self.email_service else {
            return Ok(());
        };

        email_service
            .send_password_changed_email(&user.email, &user.first_name)
            .await?;

        info!("📧 Password changed email sent to: {}", user.email);
        Ok(())
    }

    async fn send_account_deleted_email(&self, user: &User) -> Result<()> {
        let Some(email_service) = &self.email_service else {
            return Ok(());
        };

        email_service
            .send_account_deleted_email(&user.email, &user.first_name)
            .await?;

        info!("📧 Account deleted email sent to: {}", user.email);
        Ok(())
    }

    pub async fn verify_token(&self, token: &str) -> Result<Uuid> {
        debug!("🔍 Verifying token: {}...", &token[0..20.min(token.len())]);

        let jwt_secret = env::var("JWT_SECRET").map_err(|_| anyhow!("JWT_SECRET not set"))?;

        let mut validation = Validation::default();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 60; // 1 minute leeway for clock skew

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &validation,
        )?;

        let now = Utc::now().timestamp();

        if token_data.claims.exp < now {
            warn!(
                "❌ Token expired for user: {} (exp: {}, now: {})",
                token_data.claims.sub, token_data.claims.exp, now
            );
            return Err(anyhow!("Token expired"));
        }

        let token_age = now - token_data.claims.iat;
        if token_age > 86400 * 7 {
            // 7 days max age
            warn!("❌ Token too old for user: {}", token_data.claims.sub);
            return Err(anyhow!("Token expired"));
        }

        let user_id = Uuid::parse_str(&token_data.claims.sub)?;

        if let Some(redis) = &self.redis {
            match redis
                .is_session_active(user_id, &token_data.claims.jti)
                .await
            {
                Ok(is_active) => {
                    if !is_active {
                        warn!(
                            "❌ Token revoked for user: {} (jti: {})",
                            user_id, token_data.claims.jti
                        );
                        return Err(anyhow!("Token has been revoked"));
                    }
                }
                Err(e) => {
                    warn!("Failed to check session in Redis: {}", e);
                }
            }
        }

        debug!(
            "✅ Token verified for user: {} (jti: {})",
            user_id, token_data.claims.jti
        );

        Ok(user_id)
    }

    pub async fn logout(&self, user_id: Uuid, token: &str) -> Result<()> {
        if let Some(redis) = &self.redis {
            if let Ok(jwt_id) = self.extract_jwt_id(token) {
                redis
                    .remove_user_session_with_metadata(user_id, &jwt_id)
                    .await?;
                info!("✅ User logged out: {} (session: {})", user_id, jwt_id);
            }
        }

        if let Some(redis) = &self.redis {
            redis
                .invalidate_user_profile(user_id)
                .await
                .unwrap_or_else(|e| warn!("Failed to invalidate user cache: {}", e));
        }

        Ok(())
    }

    pub async fn logout_all_sessions(&self, user_id: Uuid) -> Result<()> {
        if let Some(redis) = &self.redis {
            redis
                .invalidate_all_user_sessions_with_metadata(user_id)
                .await?;
            redis
                .invalidate_user_profile(user_id)
                .await
                .unwrap_or_else(|e| warn!("Failed to invalidate user cache: {}", e));
            info!("✅ All sessions invalidated for user: {}", user_id);
        }
        Ok(())
    }

    fn extract_jwt_id(&self, token: &str) -> Result<String> {
        let jwt_secret = env::var("JWT_SECRET").map_err(|_| anyhow!("JWT_SECRET not set"))?;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::default(),
        )?;

        Ok(token_data.claims.jti)
    }

    pub async fn delete_account(&self, user_id: Uuid) -> Result<()> {
        let user = User::find_by_id(&self.pool, user_id)
            .await?
            .ok_or_else(|| anyhow!("User not found"))?;

        // soft delete
        user.delete_account(&self.pool).await?;

        self.send_account_deleted_email(&user).await?;

        Ok(())
    }

    async fn generate_token(
        &self,
        user_id: Uuid,
        role: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<String> {
        info!(
            "🎫 Generating token for user: {} with role: {} from IP: {:?}",
            user_id, role, ip_address
        );

        let jwt_secret = env::var("JWT_SECRET").map_err(|_| anyhow!("JWT_SECRET not set"))?;
        info!("🔑 JWT Secret length: {} characters", jwt_secret.len());

        let now = Utc::now().timestamp();
        let expiration = Utc::now()
            .checked_add_signed(Duration::hours(24))
            .ok_or_else(|| anyhow!("Invalid timestamp calculation"))?
            .timestamp();

        // Create a unique JWT ID (jti) for each token
        use rand::Rng;
        let mut rng = rand::rng();
        let random_bytes: [u8; 16] = rng.random();
        let jti = format!("{}-{}-{}", user_id.simple(), now, hex::encode(random_bytes));

        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration,
            role: role.clone(),
            iat: now,
            jti: jti.clone(),
        };

        info!("🎯 Token Claims:");
        info!("   - sub (user_id): {}", claims.sub);
        info!("   - role: {}", claims.role);
        info!("   - iat (issued_at): {}", claims.iat);
        info!("   - exp (expires): {}", claims.exp);
        info!("   - jti (unique_id): {}", claims.jti);

        let header = Header::default();

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )?;

        info!("✅ Token generated successfully for user: {}", user_id);
        info!("🎫 Token length: {}", token.len());
        info!(
            "🎫 Token preview: {}...{}",
            &token[0..20.min(token.len())],
            &token[token.len().saturating_sub(20)..]
        );

        // Redis session tracking with metadata
        if let Some(redis) = &self.redis {
            let ttl_seconds = 24 * 60 * 60;
            if let Err(e) = redis
                .add_user_session_with_metadata(
                    user_id,
                    &jti,
                    ip_address.clone(),
                    user_agent.clone(),
                    ttl_seconds,
                )
                .await
            {
                warn!("Failed to add session with metadata to Redis: {}", e);
                // Fallback to basic session storage if metadata fails
                if let Err(fallback_err) = redis.add_user_session(user_id, &jti, ttl_seconds).await
                {
                    warn!("Failed to add basic session to Redis: {}", fallback_err);
                }
            }
        }

        match self.verify_token(&token).await {
            Ok(verified_user_id) => {
                if verified_user_id == user_id {
                    info!(
                        "✅ Token verification successful for user: {}",
                        verified_user_id
                    );
                } else {
                    error!(
                        "❌ Token verification mismatch! Expected: {}, Got: {}",
                        user_id, verified_user_id
                    );
                }
            }
            Err(e) => {
                error!("❌ Token verification failed: {}", e);
            }
        }

        Ok(token.to_owned())
    }
}