mod common;

use axum_workout_api::AppError;
use axum_workout_api::models::user::{UserCreate, UserUpdate};
use axum_workout_api::services::UserService;
use common::{TestDb, test_data};
use uuid::Uuid;

#[tokio::test]
async fn test_register_user_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_create = UserCreate {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let result = UserService::register(pool, user_create.clone()).await;
    assert!(result.is_ok());

    let user = result.unwrap();
    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, "test@example.com");
    assert!(!user.password_hash.is_empty());
    assert_ne!(user.password_hash, "TestPassword123"); // Should be hashed

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_register_user_duplicate_username() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_create1 = UserCreate {
        username: "duplicate".to_string(),
        email: "user1@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let user_create2 = UserCreate {
        username: "duplicate".to_string(),      // Same username
        email: "user2@example.com".to_string(), // Different email
        password: "TestPassword123".to_string(),
    };

    // First registration should succeed
    let result1 = UserService::register(pool, user_create1).await;
    assert!(result1.is_ok());

    // Second registration should fail
    let result2 = UserService::register(pool, user_create2).await;
    assert!(result2.is_err());
    match result2.unwrap_err() {
        AppError::BadRequest(msg) => assert!(msg.contains("Username 'duplicate' is already taken")),
        _ => panic!("Expected BadRequest error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_register_user_duplicate_email() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_create1 = UserCreate {
        username: "user1".to_string(),
        email: "duplicate@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let user_create2 = UserCreate {
        username: "user2".to_string(),              // Different username
        email: "duplicate@example.com".to_string(), // Same email
        password: "TestPassword123".to_string(),
    };

    // First registration should succeed
    let result1 = UserService::register(pool, user_create1).await;
    assert!(result1.is_ok());

    // Second registration should fail
    let result2 = UserService::register(pool, user_create2).await;
    assert!(result2.is_err());
    match result2.unwrap_err() {
        AppError::BadRequest(msg) => {
            assert!(msg.contains("Email 'duplicate@example.com' is already registered"))
        }
        _ => panic!("Expected BadRequest error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_register_user_invalid_username() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Test empty username
    let user_create = UserCreate {
        username: "".to_string(),
        email: "test@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let result = UserService::register(pool, user_create).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::BadRequest(msg) => assert_eq!(msg, "Username cannot be empty"),
        _ => panic!("Expected BadRequest error"),
    }

    // Test short username
    let user_create = UserCreate {
        username: "ab".to_string(),
        email: "test@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let result = UserService::register(pool, user_create).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::BadRequest(msg) => assert_eq!(msg, "Username must be at least 3 characters long"),
        _ => panic!("Expected BadRequest error"),
    }

    // Test username with invalid characters
    let user_create = UserCreate {
        username: "user@name".to_string(),
        email: "test@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let result = UserService::register(pool, user_create).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::BadRequest(msg) => assert_eq!(
            msg,
            "Username can only contain letters, numbers, underscores, and hyphens"
        ),
        _ => panic!("Expected BadRequest error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_register_user_invalid_email() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Test invalid email format
    let user_create = UserCreate {
        username: "testuser".to_string(),
        email: "invalid-email".to_string(),
        password: "TestPassword123".to_string(),
    };

    let result = UserService::register(pool, user_create).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::BadRequest(msg) => assert_eq!(msg, "Invalid email format"),
        _ => panic!("Expected BadRequest error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_register_user_weak_password() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Test short password
    let user_create = UserCreate {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "short".to_string(),
    };

    let result = UserService::register(pool, user_create).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::BadRequest(msg) => assert_eq!(msg, "Password must be at least 8 characters long"),
        _ => panic!("Expected BadRequest error"),
    }

    // Test password without uppercase
    let user_create = UserCreate {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "testpassword123".to_string(),
    };

    let result = UserService::register(pool, user_create).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::BadRequest(msg) => {
            assert_eq!(msg, "Password must contain at least one uppercase letter")
        }
        _ => panic!("Expected BadRequest error"),
    }

    // Test password without lowercase
    let user_create = UserCreate {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "TESTPASSWORD123".to_string(),
    };

    let result = UserService::register(pool, user_create).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::BadRequest(msg) => {
            assert_eq!(msg, "Password must contain at least one lowercase letter")
        }
        _ => panic!("Expected BadRequest error"),
    }

    // Test password without number
    let user_create = UserCreate {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "TestPassword".to_string(),
    };

    let result = UserService::register(pool, user_create).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::BadRequest(msg) => assert_eq!(msg, "Password must contain at least one number"),
        _ => panic!("Expected BadRequest error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_authenticate_with_username_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Register a user first
    let user_create = UserCreate {
        username: "authuser".to_string(),
        email: "auth@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let registered_user = UserService::register(pool, user_create).await.unwrap();

    // Authenticate with username
    let result = UserService::authenticate(pool, "authuser", "TestPassword123").await;
    assert!(result.is_ok());

    let authenticated_user = result.unwrap();
    assert_eq!(authenticated_user.id, registered_user.id);
    assert_eq!(authenticated_user.username, "authuser");

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_authenticate_with_email_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Register a user first
    let user_create = UserCreate {
        username: "authuser".to_string(),
        email: "auth@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let registered_user = UserService::register(pool, user_create).await.unwrap();

    // Authenticate with email
    let result = UserService::authenticate(pool, "auth@example.com", "TestPassword123").await;
    assert!(result.is_ok());

    let authenticated_user = result.unwrap();
    assert_eq!(authenticated_user.id, registered_user.id);
    assert_eq!(authenticated_user.email, "auth@example.com");

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_authenticate_invalid_username() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let result = UserService::authenticate(pool, "nonexistent", "password").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::Unauthorized(msg) => assert_eq!(msg, "Invalid credentials"),
        _ => panic!("Expected Unauthorized error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_authenticate_invalid_password() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Register a user first
    let user_create = UserCreate {
        username: "authuser".to_string(),
        email: "auth@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    UserService::register(pool, user_create).await.unwrap();

    // Try to authenticate with wrong password
    let result = UserService::authenticate(pool, "authuser", "WrongPassword123").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::Unauthorized(msg) => assert_eq!(msg, "Invalid credentials"),
        _ => panic!("Expected Unauthorized error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_get_user_by_id_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Register a user first
    let user_create = test_data::create_test_user();
    let registered_user = UserService::register(pool, user_create).await.unwrap();
    let user_id = Uuid::parse_str(&registered_user.id).unwrap();

    // Get user by ID
    let result = UserService::get_user_by_id(pool, user_id).await;
    assert!(result.is_ok());

    let user = result.unwrap();
    assert_eq!(user.id, registered_user.id);
    assert_eq!(user.username, registered_user.username);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_get_user_by_id_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let non_existent_id = Uuid::new_v4();
    let result = UserService::get_user_by_id(pool, non_existent_id).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::NotFound(msg) => assert!(msg.contains("not found")),
        _ => panic!("Expected NotFound error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_get_user_by_username_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Register a user first
    let user_create = UserCreate {
        username: "findme".to_string(),
        email: "findme@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let registered_user = UserService::register(pool, user_create).await.unwrap();

    // Get user by username
    let result = UserService::get_user_by_username(pool, "findme").await;
    assert!(result.is_ok());

    let user = result.unwrap();
    assert_eq!(user.username, "findme");
    assert_eq!(user.id, registered_user.id);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_get_user_by_email_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Register a user first
    let user_create = UserCreate {
        username: "emailtest".to_string(),
        email: "findme@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let registered_user = UserService::register(pool, user_create).await.unwrap();

    // Get user by email
    let result = UserService::get_user_by_email(pool, "findme@example.com").await;
    assert!(result.is_ok());

    let user = result.unwrap();
    assert_eq!(user.email, "findme@example.com");
    assert_eq!(user.id, registered_user.id);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_get_all_users() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Register multiple users
    let user1 = UserCreate {
        username: "user1".to_string(),
        email: "user1@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    let user2 = UserCreate {
        username: "user2".to_string(),
        email: "user2@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    UserService::register(pool, user1).await.unwrap();
    UserService::register(pool, user2).await.unwrap();

    // Get all users
    let result = UserService::get_all_users(pool).await;
    assert!(result.is_ok());

    let users = result.unwrap();
    assert_eq!(users.len(), 2);

    let usernames: Vec<String> = users.iter().map(|u| u.username.clone()).collect();
    assert!(usernames.contains(&"user1".to_string()));
    assert!(usernames.contains(&"user2".to_string()));

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_update_user_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Register a user first
    let user_create = UserCreate {
        username: "updateme".to_string(),
        email: "updateme@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    let registered_user = UserService::register(pool, user_create).await.unwrap();
    let user_id = Uuid::parse_str(&registered_user.id).unwrap();

    // Update the user
    let user_update = UserUpdate {
        username: Some("updated_user".to_string()),
        email: Some("updated@example.com".to_string()),
        password: None,
    };

    let result = UserService::update_user(pool, user_id, user_update).await;
    assert!(result.is_ok());

    let updated_user = result.unwrap();
    assert_eq!(updated_user.username, "updated_user");
    assert_eq!(updated_user.email, "updated@example.com");
    assert_eq!(updated_user.password_hash, registered_user.password_hash); // Should remain unchanged

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_update_user_duplicate_username() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Register two users
    let user1_create = UserCreate {
        username: "user1".to_string(),
        email: "user1@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };
    let user2_create = UserCreate {
        username: "user2".to_string(),
        email: "user2@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    UserService::register(pool, user1_create).await.unwrap();
    let user2 = UserService::register(pool, user2_create).await.unwrap();
    let user2_id = Uuid::parse_str(&user2.id).unwrap();

    // Try to update user2's username to user1's username
    let user_update = UserUpdate {
        username: Some("user1".to_string()),
        email: None,
        password: None,
    };

    let result = UserService::update_user(pool, user2_id, user_update).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::BadRequest(msg) => assert!(msg.contains("Username 'user1' is already taken")),
        _ => panic!("Expected BadRequest error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_update_user_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let non_existent_id = Uuid::new_v4();
    let user_update = UserUpdate {
        username: Some("newname".to_string()),
        email: None,
        password: None,
    };

    let result = UserService::update_user(pool, non_existent_id, user_update).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::NotFound(msg) => assert!(msg.contains("not found")),
        _ => panic!("Expected NotFound error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_delete_user_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Register a user first
    let user_create = test_data::create_test_user();
    let registered_user = UserService::register(pool, user_create).await.unwrap();
    let user_id = Uuid::parse_str(&registered_user.id).unwrap();

    // Delete the user
    let result = UserService::delete_user(pool, user_id).await;
    assert!(result.is_ok());

    // Verify the user is deleted
    let find_result = UserService::get_user_by_id(pool, user_id).await;
    assert!(find_result.is_err());
    match find_result.unwrap_err() {
        AppError::NotFound(_) => {} // Expected
        _ => panic!("Expected NotFound error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_delete_user_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let non_existent_id = Uuid::new_v4();
    let result = UserService::delete_user(pool, non_existent_id).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::NotFound(msg) => assert!(msg.contains("not found")),
        _ => panic!("Expected NotFound error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_change_password_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Register a user first
    let user_create = UserCreate {
        username: "passwordchange".to_string(),
        email: "passwordchange@example.com".to_string(),
        password: "OldPassword123".to_string(),
    };

    let registered_user = UserService::register(pool, user_create).await.unwrap();
    let user_id = Uuid::parse_str(&registered_user.id).unwrap();

    // Change password
    let result =
        UserService::change_password(pool, user_id, "OldPassword123", "NewPassword456").await;
    assert!(result.is_ok());

    // Verify old password no longer works
    let auth_result = UserService::authenticate(pool, "passwordchange", "OldPassword123").await;
    assert!(auth_result.is_err());

    // Verify new password works
    let auth_result = UserService::authenticate(pool, "passwordchange", "NewPassword456").await;
    assert!(auth_result.is_ok());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_change_password_wrong_current_password() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Register a user first
    let user_create = UserCreate {
        username: "passwordchange".to_string(),
        email: "passwordchange@example.com".to_string(),
        password: "OldPassword123".to_string(),
    };

    let registered_user = UserService::register(pool, user_create).await.unwrap();
    let user_id = Uuid::parse_str(&registered_user.id).unwrap();

    // Try to change password with wrong current password
    let result =
        UserService::change_password(pool, user_id, "WrongPassword123", "NewPassword456").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AppError::Unauthorized(msg) => assert_eq!(msg, "Current password is incorrect"),
        _ => panic!("Expected Unauthorized error"),
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_user_exists_by_username() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Test non-existent user
    let result = UserService::user_exists_by_username(pool, "nonexistent").await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    // Register a user
    let user_create = UserCreate {
        username: "existstest".to_string(),
        email: "existstest@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    UserService::register(pool, user_create).await.unwrap();

    // Test existing user
    let result = UserService::user_exists_by_username(pool, "existstest").await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_user_exists_by_email() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Test non-existent user
    let result = UserService::user_exists_by_email(pool, "nonexistent@example.com").await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    // Register a user
    let user_create = UserCreate {
        username: "emailexists".to_string(),
        email: "emailexists@example.com".to_string(),
        password: "TestPassword123".to_string(),
    };

    UserService::register(pool, user_create).await.unwrap();

    // Test existing user
    let result = UserService::user_exists_by_email(pool, "emailexists@example.com").await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    test_db.cleanup().await;
}
