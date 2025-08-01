mod common;

use axum_workout_api::models::auth::{
    ChangePasswordRequest, JwtConfig, LoginRequest, RefreshTokenRequest, RegisterRequest,
};
use axum_workout_api::services::{AuthService, UserService};
use common::TestDb;
use uuid::Uuid;

fn create_auth_service() -> AuthService {
    let config = JwtConfig {
        secret: "test-secret-key-for-auth-tests".to_string(),
        access_token_expiry: 900,     // 15 minutes
        refresh_token_expiry: 604800, // 7 days
        issuer: "test-auth".to_string(),
    };
    AuthService::new(config)
}

#[tokio::test]
async fn test_register_user_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    let register_request = RegisterRequest {
        username: "newuser".to_string(),
        email: "newuser@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let result = auth_service.register(pool, register_request).await;
    assert!(result.is_ok());

    let login_response = result.unwrap();
    assert!(!login_response.access_token.is_empty());
    assert!(!login_response.refresh_token.is_empty());
    assert_eq!(login_response.token_type, "Bearer");
    assert_eq!(login_response.expires_in, 900);
    assert_eq!(login_response.user.username, "newuser");
    assert_eq!(login_response.user.email, "newuser@example.com");

    // Verify user was created in database
    let user = UserService::get_user_by_username(pool, "newuser").await;
    assert!(user.is_ok());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_register_duplicate_username() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    let register_request1 = RegisterRequest {
        username: "duplicate".to_string(),
        email: "user1@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let register_request2 = RegisterRequest {
        username: "duplicate".to_string(),
        email: "user2@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    // First registration should succeed
    let result1 = auth_service.register(pool, register_request1).await;
    assert!(result1.is_ok());

    // Second registration should fail
    let result2 = auth_service.register(pool, register_request2).await;
    assert!(result2.is_err());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_login_with_username_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Register user first
    let register_request = RegisterRequest {
        username: "loginuser".to_string(),
        email: "loginuser@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    auth_service.register(pool, register_request).await.unwrap();

    // Login with username
    let login_request = LoginRequest {
        identifier: "loginuser".to_string(),
        password: "TestPassword123".to_string(),
    };

    let result = auth_service.login(pool, login_request).await;
    assert!(result.is_ok());

    let login_response = result.unwrap();
    assert!(!login_response.access_token.is_empty());
    assert!(!login_response.refresh_token.is_empty());
    assert_eq!(login_response.user.username, "loginuser");

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_login_with_email_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Register user first
    let register_request = RegisterRequest {
        username: "emailuser".to_string(),
        email: "emailuser@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    auth_service.register(pool, register_request).await.unwrap();

    // Login with email
    let login_request = LoginRequest {
        identifier: "emailuser@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let result = auth_service.login(pool, login_request).await;
    assert!(result.is_ok());

    let login_response = result.unwrap();
    assert_eq!(login_response.user.email, "emailuser@example.com");

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Try to login with non-existent user
    let login_request = LoginRequest {
        identifier: "nonexistent".to_string(),
        password: "TestPassword123".to_string(),
    };

    let result = auth_service.login(pool, login_request).await;
    assert!(result.is_err());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_login_wrong_password() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Register user first
    let register_request = RegisterRequest {
        username: "wrongpass".to_string(),
        email: "wrongpass@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    auth_service.register(pool, register_request).await.unwrap();

    // Try to login with wrong password
    let login_request = LoginRequest {
        identifier: "wrongpass".to_string(),
        password: "WrongPassword123".to_string(),
    };

    let result = auth_service.login(pool, login_request).await;
    assert!(result.is_err());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_token_validation() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Register and login user
    let register_request = RegisterRequest {
        username: "tokenuser".to_string(),
        email: "tokenuser@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    let login_response = auth_service.register(pool, register_request).await.unwrap();

    // Validate access token
    let claims = auth_service.validate_token(&login_response.access_token);
    assert!(claims.is_ok());

    let claims = claims.unwrap();
    assert_eq!(claims.username, "tokenuser");
    assert_eq!(claims.email, "tokenuser@example.com");

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_token_refresh() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Register and login user
    let register_request = RegisterRequest {
        username: "refreshuser".to_string(),
        email: "refreshuser@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    let login_response = auth_service.register(pool, register_request).await.unwrap();

    // Refresh tokens
    let refresh_request = RefreshTokenRequest {
        refresh_token: login_response.refresh_token.clone(),
    };

    let result = auth_service.refresh_token(pool, refresh_request).await;
    assert!(result.is_ok());

    let token_response = result.unwrap();
    assert!(!token_response.access_token.is_empty());
    assert!(!token_response.refresh_token.is_empty());
    assert_eq!(token_response.token_type, "Bearer");

    // Verify new tokens work correctly by validating them
    let new_claims = auth_service.validate_token(&token_response.access_token);
    assert!(new_claims.is_ok());

    let claims = new_claims.unwrap();
    assert_eq!(claims.username, "refreshuser");
    assert_eq!(claims.email, "refreshuser@example.com");

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_refresh_with_invalid_token() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    let refresh_request = RefreshTokenRequest {
        refresh_token: "invalid.refresh.token".to_string(),
    };

    let result = auth_service.refresh_token(pool, refresh_request).await;
    assert!(result.is_err());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_get_current_user() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Register user
    let register_request = RegisterRequest {
        username: "currentuser".to_string(),
        email: "currentuser@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    let login_response = auth_service.register(pool, register_request).await.unwrap();

    // Validate token and get claims
    let claims = auth_service
        .validate_token(&login_response.access_token)
        .unwrap();

    // Get current user
    let result = auth_service.get_current_user(pool, &claims).await;
    assert!(result.is_ok());

    let user_response = result.unwrap();
    assert_eq!(user_response.username, "currentuser");
    assert_eq!(user_response.email, "currentuser@example.com");

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_change_password() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Register user
    let register_request = RegisterRequest {
        username: "changepass".to_string(),
        email: "changepass@example.com".to_string(),
        password: "OldPassword123".to_string(),
    };
    let login_response = auth_service.register(pool, register_request).await.unwrap();

    // Get claims from token
    let claims = auth_service
        .validate_token(&login_response.access_token)
        .unwrap();

    // Change password
    let change_request = ChangePasswordRequest {
        current_password: "OldPassword123".to_string(),
        new_password: "NewPassword456".to_string(),
    };

    let result = auth_service
        .change_password(pool, &claims, change_request)
        .await;
    assert!(result.is_ok());

    // Verify old password no longer works
    let old_login = LoginRequest {
        identifier: "changepass".to_string(),
        password: "OldPassword123".to_string(),
    };
    let old_result = auth_service.login(pool, old_login).await;
    assert!(old_result.is_err());

    // Verify new password works
    let new_login = LoginRequest {
        identifier: "changepass".to_string(),
        password: "NewPassword456".to_string(),
    };
    let new_result = auth_service.login(pool, new_login).await;
    assert!(new_result.is_ok());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_change_password_wrong_current() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Register user
    let register_request = RegisterRequest {
        username: "wrongcurrent".to_string(),
        email: "wrongcurrent@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    let login_response = auth_service.register(pool, register_request).await.unwrap();

    // Get claims from token
    let claims = auth_service
        .validate_token(&login_response.access_token)
        .unwrap();

    // Try to change password with wrong current password
    let change_request = ChangePasswordRequest {
        current_password: "WrongCurrentPassword".to_string(),
        new_password: "NewPassword456".to_string(),
    };

    let result = auth_service
        .change_password(pool, &claims, change_request)
        .await;
    assert!(result.is_err());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_delete_account() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Register user
    let register_request = RegisterRequest {
        username: "deleteuser".to_string(),
        email: "deleteuser@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    let login_response = auth_service.register(pool, register_request).await.unwrap();

    // Get claims from token
    let claims = auth_service
        .validate_token(&login_response.access_token)
        .unwrap();

    // Delete account
    let result = auth_service.delete_account(pool, &claims).await;
    assert!(result.is_ok());

    // Verify user no longer exists
    let user_result = UserService::get_user_by_id(pool, claims.user_id).await;
    assert!(user_result.is_err());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_username_availability() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Check availability of non-existent username
    let result = auth_service
        .check_username_availability(pool, "available")
        .await;
    assert!(result.is_ok());
    assert!(result.unwrap()); // Should be available

    // Register user
    let register_request = RegisterRequest {
        username: "taken".to_string(),
        email: "taken@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    auth_service.register(pool, register_request).await.unwrap();

    // Check availability of taken username
    let result = auth_service
        .check_username_availability(pool, "taken")
        .await;
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Should not be available

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_email_availability() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Check availability of non-existent email
    let result = auth_service
        .check_email_availability(pool, "available@example.com")
        .await;
    assert!(result.is_ok());
    assert!(result.unwrap()); // Should be available

    // Register user
    let register_request = RegisterRequest {
        username: "emailtest".to_string(),
        email: "taken@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    auth_service.register(pool, register_request).await.unwrap();

    // Check availability of taken email
    let result = auth_service
        .check_email_availability(pool, "taken@example.com")
        .await;
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Should not be available

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_logout() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Register user
    let register_request = RegisterRequest {
        username: "logoutuser".to_string(),
        email: "logoutuser@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    let login_response = auth_service.register(pool, register_request).await.unwrap();

    // Get claims from token
    let claims = auth_service
        .validate_token(&login_response.access_token)
        .unwrap();

    // Logout (in stateless JWT, this mainly validates the operation)
    let result = auth_service.logout(&claims).await;
    assert!(result.is_ok());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_admin_functions() {
    let test_db = TestDb::new().await;
    let _pool = &test_db.pool;
    let auth_service = create_auth_service();

    // Create admin claims (manually for testing)
    let admin_claims = axum_workout_api::models::auth::Claims {
        user_id: Uuid::new_v4(),
        username: "admin".to_string(),
        email: "admin@example.com".to_string(),
        role: axum_workout_api::models::auth::UserRole::Admin,
        exp: chrono::Utc::now().timestamp() + 3600,
        iat: chrono::Utc::now().timestamp(),
        sub: "admin".to_string(),
    };

    // Test admin check
    assert!(auth_service.is_admin(&admin_claims));

    // Create regular user claims
    let user_claims = axum_workout_api::models::auth::Claims {
        user_id: Uuid::new_v4(),
        username: "user".to_string(),
        email: "user@example.com".to_string(),
        role: axum_workout_api::models::auth::UserRole::User,
        exp: chrono::Utc::now().timestamp() + 3600,
        iat: chrono::Utc::now().timestamp(),
        sub: "user".to_string(),
    };

    // Test regular user check
    assert!(!auth_service.is_admin(&user_claims));

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_resource_access_control() {
    let test_db = TestDb::new().await;
    let _pool = &test_db.pool;
    let auth_service = create_auth_service();

    let user_id = Uuid::new_v4();
    let other_user_id = Uuid::new_v4();

    // Create user claims
    let user_claims = axum_workout_api::models::auth::Claims {
        user_id,
        username: "user".to_string(),
        email: "user@example.com".to_string(),
        role: axum_workout_api::models::auth::UserRole::User,
        exp: chrono::Utc::now().timestamp() + 3600,
        iat: chrono::Utc::now().timestamp(),
        sub: user_id.to_string(),
    };

    // User can access their own resources
    assert!(auth_service.can_access_resource(&user_claims, user_id));

    // User cannot access other user's resources
    assert!(!auth_service.can_access_resource(&user_claims, other_user_id));

    // Create admin claims
    let admin_claims = axum_workout_api::models::auth::Claims {
        user_id: other_user_id,
        username: "admin".to_string(),
        email: "admin@example.com".to_string(),
        role: axum_workout_api::models::auth::UserRole::Admin,
        exp: chrono::Utc::now().timestamp() + 3600,
        iat: chrono::Utc::now().timestamp(),
        sub: other_user_id.to_string(),
    };

    // Admin can access any resource
    assert!(auth_service.can_access_resource(&admin_claims, user_id));
    assert!(auth_service.can_access_resource(&admin_claims, other_user_id));

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_token_expiry_check() {
    let auth_service = create_auth_service();

    // Create an obviously expired token (this is a mock test)
    let expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MDk0NTkyMDB9.invalid";

    // Test with invalid token format
    assert!(auth_service.is_token_expired(expired_token));
}

#[tokio::test]
async fn test_extract_token_from_header() {
    let auth_service = create_auth_service();

    // Valid header
    let valid_header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let result = auth_service.extract_token_from_header(valid_header);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");

    // Invalid header format
    let invalid_header = "Basic dXNlcjpwYXNz";
    let result = auth_service.extract_token_from_header(invalid_header);
    assert!(result.is_err());

    // Missing token
    let empty_header = "Bearer ";
    let result = auth_service.extract_token_from_header(empty_header);
    assert!(result.is_err());
}
