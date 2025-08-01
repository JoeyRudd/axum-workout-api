use crate::errors::AppError;
use crate::models::auth::{ApiResponse, UserResponse};
use crate::models::user::UserUpdate;
use crate::routes::AppState;
use crate::services::UserService;
use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use serde::Deserialize;

/// Get user by ID
/// GET /api/users/{user_id}
/// Requires: Authentication (users can only see their own profile, admins can see any)
pub async fn get_user_by_id(
    State(_state): State<AppState>,
    Path(_user_id): Path<String>,
) -> Result<Json<UserResponse>, AppError> {
    // TODO: Add authentication - for now return error
    Err(AppError::Unauthorized(
        "Authentication not implemented yet".to_string(),
    ))
}

/// Get user by username
/// GET /api/users/username/{username}
/// Requires: Authentication (public profile view)
pub async fn get_user_by_username(
    State(_state): State<AppState>,
    Path(_username): Path<String>,
) -> Result<Json<UserResponse>, AppError> {
    // TODO: Add authentication - for now return error
    Err(AppError::Unauthorized(
        "Authentication not implemented yet".to_string(),
    ))
}

/// Update user profile
/// PUT /api/users/{user_id}
/// Requires: Authentication + ownership (users can only update their own profile)
pub async fn update_user(
    State(_state): State<AppState>,
    Path(_user_id): Path<String>,
    Json(_user_update): Json<UserUpdate>,
) -> Result<Json<UserResponse>, AppError> {
    // TODO: Add authentication - for now return error
    Err(AppError::Unauthorized(
        "Authentication not implemented yet".to_string(),
    ))
}

/// Delete user account
/// DELETE /api/users/{user_id}
/// Requires: Authentication + ownership (users can only delete their own account, admins can delete any)
pub async fn delete_user(
    State(_state): State<AppState>,
    Path(_user_id): Path<String>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    // TODO: Add authentication - for now return error
    Err(AppError::Unauthorized(
        "Authentication not implemented yet".to_string(),
    ))
}

/// List users with pagination (Admin only)
/// GET /api/users?page=1&limit=10
/// Requires: Admin authentication
pub async fn list_users(
    State(_state): State<AppState>,
    Query(_params): Query<ListUsersQuery>,
) -> Result<Json<PaginatedUsersResponse>, AppError> {
    // TODO: Add admin authentication - for now return error
    Err(AppError::Unauthorized(
        "Admin authentication not implemented yet".to_string(),
    ))
}

/// Check if user exists by username
/// GET /api/users/exists/username/{username}
/// Public endpoint
pub async fn check_user_exists_by_username(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<ExistenceResponse>, AppError> {
    let exists = UserService::user_exists_by_username(&state.pool, &username).await?;

    Ok(Json(ExistenceResponse {
        exists,
        message: if exists {
            format!("User '{}' exists", username)
        } else {
            format!("User '{}' does not exist", username)
        },
    }))
}

/// Check if user exists by email
/// GET /api/users/exists/email/{email}
/// Public endpoint
pub async fn check_user_exists_by_email(
    State(state): State<AppState>,
    Path(email): Path<String>,
) -> Result<Json<ExistenceResponse>, AppError> {
    let exists = UserService::user_exists_by_email(&state.pool, &email).await?;

    Ok(Json(ExistenceResponse {
        exists,
        message: if exists {
            format!("User with email '{}' exists", email)
        } else {
            format!("User with email '{}' does not exist", email)
        },
    }))
}

/// Get current user's profile (convenience endpoint)
/// GET /api/users/me
/// Requires: Authentication
pub async fn get_current_user_profile(
    State(_state): State<AppState>,
) -> Result<Json<UserResponse>, AppError> {
    // TODO: Add authentication - for now return error
    Err(AppError::Unauthorized(
        "Authentication not implemented yet".to_string(),
    ))
}

// Query parameter structs
#[derive(Deserialize)]
pub struct ListUsersQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

// Response structs
#[derive(serde::Serialize)]
pub struct PaginatedUsersResponse {
    pub users: Vec<UserResponse>,
    pub page: u32,
    pub limit: u32,
    pub total: u32,
    pub has_next: bool,
    pub has_previous: bool,
}

#[derive(serde::Serialize)]
pub struct ExistenceResponse {
    pub exists: bool,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::auth::UserRole;

    fn create_test_claims() -> crate::models::auth::Claims {
        crate::models::auth::Claims {
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
    fn test_paginated_users_response_serialization() {
        let response = PaginatedUsersResponse {
            users: vec![],
            page: 1,
            limit: 10,
            total: 0,
            has_next: false,
            has_previous: false,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"page\":1"));
        assert!(json.contains("\"limit\":10"));
        assert!(json.contains("\"total\":0"));
    }

    #[test]
    fn test_existence_response_serialization() {
        let response = ExistenceResponse {
            exists: true,
            message: "User exists".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"exists\":true"));
        assert!(json.contains("\"message\":\"User exists\""));
    }

    #[test]
    fn test_list_users_query_deserialization() {
        let json = r#"{"page":2,"limit":20}"#;
        let query: ListUsersQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.page, Some(2));
        assert_eq!(query.limit, Some(20));
    }
}
