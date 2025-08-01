use crate::errors::AppError;
use crate::models::auth::{
    ChangePasswordRequest, Claims, JwtConfig, LoginRequest, LoginResponse, RefreshTokenRequest,
    RegisterRequest, TokenResponse, UserResponse,
};
use crate::models::user::{UserCreate, UserUpdate};
use crate::services::{JwtService, UserService};
use sqlx::PgPool;
use uuid::Uuid;

pub struct AuthService {
    jwt_service: JwtService,
}

impl AuthService {
    pub fn new(jwt_config: JwtConfig) -> Self {
        Self {
            jwt_service: JwtService::new(jwt_config),
        }
    }

    pub fn default() -> Self {
        Self {
            jwt_service: JwtService::default(),
        }
    }

    /// Register a new user and return tokens
    pub async fn register(
        &self,
        pool: &PgPool,
        register_request: RegisterRequest,
    ) -> Result<LoginResponse, AppError> {
        // Create user through UserService
        let user_create = UserCreate {
            username: register_request.username,
            email: register_request.email,
            password: register_request.password,
        };

        let user = UserService::register(pool, user_create).await?;

        // Generate tokens for the new user
        let (access_token, refresh_token) = self.jwt_service.generate_tokens(&user)?;

        Ok(LoginResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.jwt_service.config().access_token_expiry,
            user: UserResponse::from(user),
        })
    }

    /// Authenticate user and return tokens
    pub async fn login(
        &self,
        pool: &PgPool,
        login_request: LoginRequest,
    ) -> Result<LoginResponse, AppError> {
        // Authenticate user through UserService
        let user =
            UserService::authenticate(pool, &login_request.identifier, &login_request.password)
                .await?;

        // Generate tokens for authenticated user
        let (access_token, refresh_token) = self.jwt_service.generate_tokens(&user)?;

        Ok(LoginResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.jwt_service.config().access_token_expiry,
            user: UserResponse::from(user),
        })
    }

    /// Refresh access token using refresh token
    pub async fn refresh_token(
        &self,
        pool: &PgPool,
        refresh_request: RefreshTokenRequest,
    ) -> Result<TokenResponse, AppError> {
        // Validate refresh token
        let refresh_claims = self
            .jwt_service
            .validate_refresh_token(&refresh_request.refresh_token)?;

        // Get user from database to ensure they still exist
        let user = UserService::get_user_by_id(pool, refresh_claims.user_id).await?;

        // Generate new tokens (token rotation for security)
        let new_access_token = self
            .jwt_service
            .refresh_access_token(&refresh_request.refresh_token, &user)?;
        let new_refresh_token = self
            .jwt_service
            .rotate_refresh_token(&refresh_request.refresh_token, &user)?;

        Ok(TokenResponse {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.jwt_service.config().access_token_expiry,
        })
    }

    /// Get current user from token claims
    pub async fn get_current_user(
        &self,
        pool: &PgPool,
        claims: &Claims,
    ) -> Result<UserResponse, AppError> {
        let user = UserService::get_user_by_id(pool, claims.user_id).await?;
        Ok(UserResponse::from(user))
    }

    /// Update current user profile
    pub async fn update_profile(
        &self,
        pool: &PgPool,
        claims: &Claims,
        user_update: UserUpdate,
    ) -> Result<UserResponse, AppError> {
        let updated_user = UserService::update_user(pool, claims.user_id, user_update).await?;
        Ok(UserResponse::from(updated_user))
    }

    /// Change user password
    pub async fn change_password(
        &self,
        pool: &PgPool,
        claims: &Claims,
        change_request: ChangePasswordRequest,
    ) -> Result<(), AppError> {
        UserService::change_password(
            pool,
            claims.user_id,
            &change_request.current_password,
            &change_request.new_password,
        )
        .await
    }

    /// Delete user account
    pub async fn delete_account(&self, pool: &PgPool, claims: &Claims) -> Result<(), AppError> {
        UserService::delete_user(pool, claims.user_id).await
    }

    /// Validate access token and return claims
    pub fn validate_token(&self, token: &str) -> Result<Claims, AppError> {
        self.jwt_service.validate_access_token(token)
    }

    /// Extract token from Authorization header
    pub fn extract_token_from_header<'a>(&self, auth_header: &'a str) -> Result<&'a str, AppError> {
        JwtService::extract_token_from_header(auth_header)
    }

    /// Check if user has admin role
    pub fn is_admin(&self, claims: &Claims) -> bool {
        matches!(claims.role, crate::models::auth::UserRole::Admin)
    }

    /// Check if user can access resource (ownership check)
    pub fn can_access_resource(&self, claims: &Claims, resource_user_id: Uuid) -> bool {
        // Admins can access anything, users can only access their own resources
        self.is_admin(claims) || claims.user_id == resource_user_id
    }

    /// Validate token and check resource access
    pub async fn validate_and_authorize(
        &self,
        pool: &PgPool,
        token: &str,
        resource_user_id: Option<Uuid>,
    ) -> Result<Claims, AppError> {
        // Validate token
        let claims = self.validate_token(token)?;

        // Verify user still exists
        UserService::get_user_by_id(pool, claims.user_id).await?;

        // Check resource access if resource_user_id is provided
        if let Some(resource_owner_id) = resource_user_id {
            if !self.can_access_resource(&claims, resource_owner_id) {
                return Err(AppError::Unauthorized(
                    "You don't have permission to access this resource".to_string(),
                ));
            }
        }

        Ok(claims)
    }

    /// Get JWT service configuration
    pub fn jwt_config(&self) -> &JwtConfig {
        self.jwt_service.config()
    }

    /// Check if token is expired
    pub fn is_token_expired(&self, token: &str) -> bool {
        self.jwt_service.is_token_expired(token)
    }

    /// Generate tokens for existing user (utility method)
    pub fn generate_tokens_for_user(
        &self,
        user: &crate::models::user::User,
    ) -> Result<(String, String), AppError> {
        self.jwt_service.generate_tokens(user)
    }

    /// Logout user (in a stateless JWT system, this is mainly for client-side cleanup)
    /// In a production system, you might want to maintain a blacklist of revoked tokens
    pub async fn logout(&self, _claims: &Claims) -> Result<(), AppError> {
        // In a stateless JWT system, logout is handled client-side by discarding tokens
        // For enhanced security, you could implement token blacklisting here
        Ok(())
    }

    /// Admin function: Get all users
    pub async fn get_all_users(
        &self,
        pool: &PgPool,
        claims: &Claims,
    ) -> Result<Vec<UserResponse>, AppError> {
        // Check admin permissions
        if !self.is_admin(claims) {
            return Err(AppError::Unauthorized("Admin access required".to_string()));
        }

        let users = UserService::get_all_users(pool).await?;
        Ok(users.into_iter().map(UserResponse::from).collect())
    }

    /// Admin function: Delete any user
    pub async fn admin_delete_user(
        &self,
        pool: &PgPool,
        claims: &Claims,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        // Check admin permissions
        if !self.is_admin(claims) {
            return Err(AppError::Unauthorized("Admin access required".to_string()));
        }

        UserService::delete_user(pool, user_id).await
    }

    /// Check if username is available
    pub async fn check_username_availability(
        &self,
        pool: &PgPool,
        username: &str,
    ) -> Result<bool, AppError> {
        let exists = UserService::user_exists_by_username(pool, username).await?;
        Ok(!exists)
    }

    /// Check if email is available
    pub async fn check_email_availability(
        &self,
        pool: &PgPool,
        email: &str,
    ) -> Result<bool, AppError> {
        let exists = UserService::user_exists_by_email(pool, email).await?;
        Ok(!exists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::auth::JwtConfig;

    fn create_auth_service() -> AuthService {
        let config = JwtConfig {
            secret: "test-secret-key".to_string(),
            access_token_expiry: 900,     // 15 minutes
            refresh_token_expiry: 604800, // 7 days
            issuer: "test".to_string(),
        };
        AuthService::new(config)
    }

    #[test]
    fn test_auth_service_creation() {
        let auth_service = create_auth_service();
        assert_eq!(auth_service.jwt_config().secret, "test-secret-key");
        assert_eq!(auth_service.jwt_config().access_token_expiry, 900);
    }

    #[test]
    fn test_admin_check() {
        let auth_service = create_auth_service();

        let admin_claims = Claims {
            user_id: uuid::Uuid::new_v4(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            role: crate::models::auth::UserRole::Admin,
            exp: 0,
            iat: 0,
            sub: "admin".to_string(),
        };

        let user_claims = Claims {
            user_id: uuid::Uuid::new_v4(),
            username: "user".to_string(),
            email: "user@example.com".to_string(),
            role: crate::models::auth::UserRole::User,
            exp: 0,
            iat: 0,
            sub: "user".to_string(),
        };

        assert!(auth_service.is_admin(&admin_claims));
        assert!(!auth_service.is_admin(&user_claims));
    }

    #[test]
    fn test_resource_access() {
        let auth_service = create_auth_service();
        let user_id = uuid::Uuid::new_v4();
        let other_user_id = uuid::Uuid::new_v4();

        let user_claims = Claims {
            user_id,
            username: "user".to_string(),
            email: "user@example.com".to_string(),
            role: crate::models::auth::UserRole::User,
            exp: 0,
            iat: 0,
            sub: user_id.to_string(),
        };

        let admin_claims = Claims {
            user_id: other_user_id,
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            role: crate::models::auth::UserRole::Admin,
            exp: 0,
            iat: 0,
            sub: other_user_id.to_string(),
        };

        // User can access their own resources
        assert!(auth_service.can_access_resource(&user_claims, user_id));

        // User cannot access other user's resources
        assert!(!auth_service.can_access_resource(&user_claims, other_user_id));

        // Admin can access any resource
        assert!(auth_service.can_access_resource(&admin_claims, user_id));
        assert!(auth_service.can_access_resource(&admin_claims, other_user_id));
    }
}
