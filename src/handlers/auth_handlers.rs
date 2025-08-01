use crate::errors::AppError;

use crate::models::auth::{
    ApiResponse, ChangePasswordRequest, LoginRequest, LoginResponse, RefreshTokenRequest,
    RegisterRequest, TokenResponse, UserResponse,
};
use crate::models::user::UserUpdate;
use crate::routes::AppState;

use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use serde::Deserialize;

/// Register a new user
/// POST /api/auth/register
pub async fn register(
    State(state): State<AppState>,
    Json(register_request): Json<RegisterRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let login_response = state
        .auth_service
        .register(&state.pool, register_request)
        .await?;
    Ok(Json(login_response))
}

/// Login user and return JWT tokens
/// POST /api/auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let login_response = state.auth_service.login(&state.pool, login_request).await?;
    Ok(Json(login_response))
}

/// Refresh access token using refresh token
/// POST /api/auth/refresh
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(refresh_request): Json<RefreshTokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let token_response = state
        .auth_service
        .refresh_token(&state.pool, refresh_request)
        .await?;
    Ok(Json(token_response))
}

/// Get current authenticated user
/// GET /api/auth/me
/// Requires: Authentication middleware
pub async fn me(State(_state): State<AppState>) -> Result<Json<UserResponse>, AppError> {
    // TODO: Add authentication - for now return error
    Err(AppError::Unauthorized(
        "Authentication not implemented yet".to_string(),
    ))
}

/// Update current user profile
/// PUT /api/auth/profile
/// Requires: Authentication middleware
pub async fn update_profile(
    State(_state): State<AppState>,
    Json(_user_update): Json<UserUpdate>,
) -> Result<Json<UserResponse>, AppError> {
    // TODO: Add authentication - for now return error
    Err(AppError::Unauthorized(
        "Authentication not implemented yet".to_string(),
    ))
}

/// Change user password
/// POST /api/auth/change-password
/// Requires: Authentication middleware
pub async fn change_password(
    State(_state): State<AppState>,
    Json(_change_request): Json<ChangePasswordRequest>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    // TODO: Add authentication - for now return error
    Err(AppError::Unauthorized(
        "Authentication not implemented yet".to_string(),
    ))
}

/// Delete current user account
/// DELETE /api/auth/account
/// Requires: Authentication middleware
pub async fn delete_account(
    State(_state): State<AppState>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    // TODO: Add authentication - for now return error
    Err(AppError::Unauthorized(
        "Authentication not implemented yet".to_string(),
    ))
}

/// Logout user (client-side token cleanup)
/// POST /api/auth/logout
/// Requires: Authentication middleware
pub async fn logout(State(_state): State<AppState>) -> Result<Json<ApiResponse<()>>, AppError> {
    // TODO: Add authentication - for now return error
    Err(AppError::Unauthorized(
        "Authentication not implemented yet".to_string(),
    ))
}

/// Check username availability
/// GET /api/auth/check-username?username=test
/// Public endpoint
pub async fn check_username_availability(
    State(state): State<AppState>,
    Query(params): Query<UsernameQuery>,
) -> Result<Json<AvailabilityResponse>, AppError> {
    let is_available = state
        .auth_service
        .check_username_availability(&state.pool, &params.username)
        .await?;

    Ok(Json(AvailabilityResponse {
        available: is_available,
        message: if is_available {
            "Username is available".to_string()
        } else {
            "Username is already taken".to_string()
        },
    }))
}

/// Check email availability
/// GET /api/auth/check-email?email=test@example.com
/// Public endpoint
pub async fn check_email_availability(
    State(state): State<AppState>,
    Query(params): Query<EmailQuery>,
) -> Result<Json<AvailabilityResponse>, AppError> {
    let is_available = state
        .auth_service
        .check_email_availability(&state.pool, &params.email)
        .await?;

    Ok(Json(AvailabilityResponse {
        available: is_available,
        message: if is_available {
            "Email is available".to_string()
        } else {
            "Email is already registered".to_string()
        },
    }))
}

// Admin endpoints

/// Get all users (Admin only)
/// GET /api/admin/users
/// Requires: Admin middleware
pub async fn admin_get_all_users(
    State(_state): State<AppState>,
) -> Result<Json<Vec<UserResponse>>, AppError> {
    // TODO: Add admin authentication - for now return error
    Err(AppError::Unauthorized(
        "Admin authentication not implemented yet".to_string(),
    ))
}

/// Delete any user (Admin only)
/// DELETE /api/admin/users/{user_id}
/// Requires: Admin middleware
pub async fn admin_delete_user(
    State(_state): State<AppState>,
    Path(_user_id): Path<String>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    // TODO: Add admin authentication - for now return error
    Err(AppError::Unauthorized(
        "Admin authentication not implemented yet".to_string(),
    ))
}

// Query parameter structs
#[derive(Deserialize)]
pub struct UsernameQuery {
    pub username: String,
}

#[derive(Deserialize)]
pub struct EmailQuery {
    pub email: String,
}

// Response structs
#[derive(serde::Serialize)]
pub struct AvailabilityResponse {
    pub available: bool,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::auth::{Claims, UserRole};

    fn create_test_claims() -> Claims {
        Claims {
            user_id: uuid::Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            role: UserRole::User,
            exp: chrono::Utc::now().timestamp() + 3600,
            iat: chrono::Utc::now().timestamp(),
            sub: "testuser".to_string(),
        }
    }

    #[test]
    fn test_availability_response_serialization() {
        let response = AvailabilityResponse {
            available: true,
            message: "Username is available".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"available\":true"));
        assert!(json.contains("\"message\":\"Username is available\""));
    }

    #[test]
    fn test_username_query_deserialization() {
        let json = r#"{"username":"testuser"}"#;
        let query: UsernameQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.username, "testuser");
    }

    #[test]
    fn test_email_query_deserialization() {
        let json = r#"{"email":"test@example.com"}"#;
        let query: EmailQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.email, "test@example.com");
    }
}
