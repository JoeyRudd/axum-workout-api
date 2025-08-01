use crate::errors::AppError;
use crate::models::auth::{Claims, JwtConfig, RefreshClaims, UserRole};
use crate::models::user::User;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use uuid::Uuid;

pub struct JwtService {
    config: JwtConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtService {
    pub fn new(config: JwtConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.secret.as_ref());
        let decoding_key = DecodingKey::from_secret(config.secret.as_ref());

        Self {
            config,
            encoding_key,
            decoding_key,
        }
    }

    /// Generate access token for authenticated user
    pub fn generate_access_token(&self, user: &User) -> Result<String, AppError> {
        let now = Utc::now();
        let expiry = now + Duration::seconds(self.config.access_token_expiry);

        let claims = Claims {
            user_id: Uuid::parse_str(&user.id)
                .map_err(|e| AppError::InternalServerError(format!("Invalid user ID: {}", e)))?,
            username: user.username.clone(),
            email: user.email.clone(),
            role: UserRole::User, // Default role, can be extended
            exp: expiry.timestamp(),
            iat: now.timestamp(),
            sub: user.id.clone(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::InternalServerError(format!("Failed to generate token: {}", e)))
    }

    /// Generate refresh token for user
    pub fn generate_refresh_token(&self, user: &User) -> Result<String, AppError> {
        let now = Utc::now();
        let expiry = now + Duration::seconds(self.config.refresh_token_expiry);

        let claims = RefreshClaims {
            user_id: Uuid::parse_str(&user.id)
                .map_err(|e| AppError::InternalServerError(format!("Invalid user ID: {}", e)))?,
            username: user.username.clone(),
            exp: expiry.timestamp(),
            iat: now.timestamp(),
            sub: user.id.clone(),
            token_type: "refresh".to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key).map_err(|e| {
            AppError::InternalServerError(format!("Failed to generate refresh token: {}", e))
        })
    }

    /// Generate both access and refresh tokens
    pub fn generate_tokens(&self, user: &User) -> Result<(String, String), AppError> {
        let access_token = self.generate_access_token(user)?;
        let refresh_token = self.generate_refresh_token(user)?;
        Ok((access_token, refresh_token))
    }

    /// Validate and decode access token
    pub fn validate_access_token(&self, token: &str) -> Result<Claims, AppError> {
        let validation = Validation::new(Algorithm::HS256);

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    AppError::Unauthorized("Token has expired".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    AppError::Unauthorized("Invalid token".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    AppError::Unauthorized("Invalid token signature".to_string())
                }
                _ => AppError::Unauthorized("Token validation failed".to_string()),
            })
    }

    /// Validate and decode refresh token
    pub fn validate_refresh_token(&self, token: &str) -> Result<RefreshClaims, AppError> {
        let validation = Validation::new(Algorithm::HS256);

        decode::<RefreshClaims>(token, &self.decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    AppError::Unauthorized("Refresh token has expired".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    AppError::Unauthorized("Invalid refresh token".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    AppError::Unauthorized("Invalid refresh token signature".to_string())
                }
                _ => AppError::Unauthorized("Refresh token validation failed".to_string()),
            })
    }

    /// Extract token from Authorization header
    pub fn extract_token_from_header(auth_header: &str) -> Result<&str, AppError> {
        if !auth_header.starts_with("Bearer ") {
            return Err(AppError::Unauthorized(
                "Invalid authorization header format".to_string(),
            ));
        }

        let token = auth_header.trim_start_matches("Bearer ");
        if token.is_empty() {
            return Err(AppError::Unauthorized("Missing token".to_string()));
        }

        Ok(token)
    }

    /// Check if token is expired (without validating signature)
    pub fn is_token_expired(&self, token: &str) -> bool {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.insecure_disable_signature_validation();

        if let Ok(token_data) = decode::<Claims>(token, &self.decoding_key, &validation) {
            let now = Utc::now().timestamp();
            token_data.claims.exp < now
        } else {
            true // If we can't decode it, consider it expired
        }
    }

    /// Get token expiry time
    pub fn get_token_expiry(&self, token: &str) -> Result<i64, AppError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.insecure_disable_signature_validation();

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|token_data| token_data.claims.exp)
            .map_err(|_| AppError::BadRequest("Invalid token format".to_string()))
    }

    /// Get configuration
    pub fn config(&self) -> &JwtConfig {
        &self.config
    }

    /// Create a new JWT service with default configuration
    pub fn default() -> Self {
        Self::new(JwtConfig::default())
    }

    /// Refresh access token using valid refresh token
    pub fn refresh_access_token(
        &self,
        refresh_token: &str,
        user: &User,
    ) -> Result<String, AppError> {
        // Validate refresh token first
        let refresh_claims = self.validate_refresh_token(refresh_token)?;

        // Ensure the refresh token is for the same user
        if refresh_claims.user_id
            != Uuid::parse_str(&user.id)
                .map_err(|e| AppError::InternalServerError(format!("Invalid user ID: {}", e)))?
        {
            return Err(AppError::Unauthorized(
                "Refresh token does not match user".to_string(),
            ));
        }

        // Generate new access token
        self.generate_access_token(user)
    }

    /// Generate new refresh token (for token rotation)
    pub fn rotate_refresh_token(
        &self,
        old_refresh_token: &str,
        user: &User,
    ) -> Result<String, AppError> {
        // Validate old refresh token
        let refresh_claims = self.validate_refresh_token(old_refresh_token)?;

        // Ensure the refresh token is for the same user
        if refresh_claims.user_id
            != Uuid::parse_str(&user.id)
                .map_err(|e| AppError::InternalServerError(format!("Invalid user ID: {}", e)))?
        {
            return Err(AppError::Unauthorized(
                "Refresh token does not match user".to_string(),
            ));
        }

        // Generate new refresh token
        self.generate_refresh_token(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::user::User;

    fn create_test_user() -> User {
        User {
            id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hashed_password".to_string(),
            created_at: "2023-01-01T00:00:00Z".to_string(),
        }
    }

    fn create_jwt_service() -> JwtService {
        let config = JwtConfig {
            secret: "test-secret-key".to_string(),
            access_token_expiry: 900,     // 15 minutes
            refresh_token_expiry: 604800, // 7 days
            issuer: "test".to_string(),
        };
        JwtService::new(config)
    }

    #[test]
    fn test_generate_access_token() {
        let service = create_jwt_service();
        let user = create_test_user();

        let token = service.generate_access_token(&user).unwrap();
        assert!(!token.is_empty());

        // Should be able to validate the token
        let claims = service.validate_access_token(&token).unwrap();
        assert_eq!(claims.username, "testuser");
        assert_eq!(claims.email, "test@example.com");
    }

    #[test]
    fn test_generate_refresh_token() {
        let service = create_jwt_service();
        let user = create_test_user();

        let token = service.generate_refresh_token(&user).unwrap();
        assert!(!token.is_empty());

        // Should be able to validate the refresh token
        let claims = service.validate_refresh_token(&token).unwrap();
        assert_eq!(claims.username, "testuser");
        assert_eq!(claims.token_type, "refresh");
    }

    #[test]
    fn test_token_validation() {
        let service = create_jwt_service();
        let user = create_test_user();

        let (access_token, refresh_token) = service.generate_tokens(&user).unwrap();

        // Access token should validate
        let claims = service.validate_access_token(&access_token).unwrap();
        assert_eq!(
            claims.user_id.to_string(),
            "123e4567-e89b-12d3-a456-426614174000"
        );

        // Refresh token should validate
        let refresh_claims = service.validate_refresh_token(&refresh_token).unwrap();
        assert_eq!(
            refresh_claims.user_id.to_string(),
            "123e4567-e89b-12d3-a456-426614174000"
        );
    }

    #[test]
    fn test_invalid_token() {
        let service = create_jwt_service();

        let result = service.validate_access_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_token_from_header() {
        let valid_header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let token = JwtService::extract_token_from_header(valid_header).unwrap();
        assert_eq!(token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");

        let invalid_header = "Basic dXNlcjpwYXNz";
        let result = JwtService::extract_token_from_header(invalid_header);
        assert!(result.is_err());
    }
}
