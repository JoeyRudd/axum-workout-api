use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::user::User;

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub role: UserRole,
    pub exp: i64,    // Expiration timestamp
    pub iat: i64,    // Issued at timestamp
    pub sub: String, // Subject (user_id as string)
}

/// User roles for authorization
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    User,
    Admin,
}

impl Default for UserRole {
    fn default() -> Self {
        UserRole::User
    }
}

/// Login request payload
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub identifier: String, // Can be username or email
    pub password: String,
}

/// Registration request payload
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Login response with tokens and user info
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64, // Access token expiration in seconds
    pub user: UserResponse,
}

/// Token refresh request
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Token refresh response
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// User response (public user data)
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: UserRole,
    pub created_at: String,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            role: UserRole::User, // Default role, could be extended with role field in User model
            created_at: user.created_at,
        }
    }
}

/// Refresh token claims (for refresh tokens)
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub user_id: Uuid,
    pub username: String,
    pub exp: i64,
    pub iat: i64,
    pub sub: String,
    pub token_type: String, // "refresh"
}

/// Password change request
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Generic API response wrapper
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
        }
    }

    pub fn success_with_message(data: T, message: String) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: Some(message),
        }
    }
}

impl ApiResponse<()> {
    pub fn success_message(message: String) -> Self {
        Self {
            success: true,
            data: None,
            message: Some(message),
        }
    }
}

/// JWT configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_expiry: i64,  // in seconds
    pub refresh_token_expiry: i64, // in seconds
    pub issuer: String,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string()),
            access_token_expiry: 15 * 60,        // 15 minutes
            refresh_token_expiry: 7 * 24 * 3600, // 7 days
            issuer: "axum-workout-api".to_string(),
        }
    }
}
