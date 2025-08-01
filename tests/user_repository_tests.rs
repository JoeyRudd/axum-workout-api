mod common;

use axum_workout_api::models::user::UserUpdate;
use axum_workout_api::repositories::UserRepository;
use common::{TestDb, test_data};
use uuid::Uuid;

#[tokio::test]
async fn test_insert_user_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_create = test_data::create_test_user();
    let password_hash = "hashed_password_123".to_string();

    let result = UserRepository::insert(pool, user_create.clone(), password_hash.clone()).await;

    assert!(result.is_ok());
    let user = result.unwrap();

    assert_eq!(user.username, user_create.username);
    assert_eq!(user.email, user_create.email);
    assert_eq!(user.password_hash, password_hash);
    assert!(!user.id.is_empty());
    assert!(!user.created_at.is_empty());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_insert_user_duplicate_username() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_create = test_data::create_test_user_with_data("duplicate_user", "user1@test.com");
    let password_hash = "hashed_password_123".to_string();

    // Insert first user
    let result1 = UserRepository::insert(pool, user_create.clone(), password_hash.clone()).await;
    assert!(result1.is_ok());

    // Try to insert user with same username but different email
    let user_create2 = test_data::create_test_user_with_data("duplicate_user", "user2@test.com");
    let result2 = UserRepository::insert(pool, user_create2, password_hash).await;
    assert!(result2.is_err());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_insert_user_duplicate_email() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_create = test_data::create_test_user_with_data("user1", "duplicate@test.com");
    let password_hash = "hashed_password_123".to_string();

    // Insert first user
    let result1 = UserRepository::insert(pool, user_create.clone(), password_hash.clone()).await;
    assert!(result1.is_ok());

    // Try to insert user with same email but different username
    let user_create2 = test_data::create_test_user_with_data("user2", "duplicate@test.com");
    let result2 = UserRepository::insert(pool, user_create2, password_hash).await;
    assert!(result2.is_err());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_id_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert a user first
    let user_create = test_data::create_test_user();
    let password_hash = "hashed_password_123".to_string();
    let inserted_user = UserRepository::insert(pool, user_create, password_hash)
        .await
        .unwrap();
    let user_id = Uuid::parse_str(&inserted_user.id).unwrap();

    // Find the user by ID
    let result = UserRepository::find_by_id(pool, user_id).await;
    assert!(result.is_ok());

    let found_user = result.unwrap();
    assert!(found_user.is_some());

    let user = found_user.unwrap();
    assert_eq!(user.id, inserted_user.id);
    assert_eq!(user.username, inserted_user.username);
    assert_eq!(user.email, inserted_user.email);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_id_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let non_existent_id = Uuid::new_v4();
    let result = UserRepository::find_by_id(pool, non_existent_id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_username_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert a user first
    let user_create = test_data::create_test_user_with_data("findme", "findme@test.com");
    let password_hash = "hashed_password_123".to_string();
    let inserted_user = UserRepository::insert(pool, user_create, password_hash)
        .await
        .unwrap();

    // Find the user by username
    let result = UserRepository::find_by_username(pool, "findme").await;
    assert!(result.is_ok());

    let found_user = result.unwrap();
    assert!(found_user.is_some());

    let user = found_user.unwrap();
    assert_eq!(user.username, "findme");
    assert_eq!(user.id, inserted_user.id);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_username_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let result = UserRepository::find_by_username(pool, "nonexistent").await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_email_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert a user first
    let user_create = test_data::create_test_user_with_data("emailtest", "findemail@test.com");
    let password_hash = "hashed_password_123".to_string();
    let inserted_user = UserRepository::insert(pool, user_create, password_hash)
        .await
        .unwrap();

    // Find the user by email
    let result = UserRepository::find_by_email(pool, "findemail@test.com").await;
    assert!(result.is_ok());

    let found_user = result.unwrap();
    assert!(found_user.is_some());

    let user = found_user.unwrap();
    assert_eq!(user.email, "findemail@test.com");
    assert_eq!(user.id, inserted_user.id);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_email_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let result = UserRepository::find_by_email(pool, "nonexistent@test.com").await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_all_users() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert multiple users
    let user1 = test_data::create_test_user_with_data("user1", "user1@test.com");
    let user2 = test_data::create_test_user_with_data("user2", "user2@test.com");
    let user3 = test_data::create_test_user_with_data("user3", "user3@test.com");

    let password_hash = "hashed_password_123".to_string();

    UserRepository::insert(pool, user1, password_hash.clone())
        .await
        .unwrap();
    UserRepository::insert(pool, user2, password_hash.clone())
        .await
        .unwrap();
    UserRepository::insert(pool, user3, password_hash)
        .await
        .unwrap();

    // Find all users
    let result = UserRepository::find_all(pool).await;
    assert!(result.is_ok());

    let users = result.unwrap();
    assert_eq!(users.len(), 3);

    // Should be ordered by created_at DESC, so most recent first
    let usernames: Vec<String> = users.iter().map(|u| u.username.clone()).collect();
    assert!(usernames.contains(&"user1".to_string()));
    assert!(usernames.contains(&"user2".to_string()));
    assert!(usernames.contains(&"user3".to_string()));

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_update_user_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert a user first
    let user_create = test_data::create_test_user_with_data("updateme", "updateme@test.com");
    let password_hash = "hashed_password_123".to_string();
    let inserted_user = UserRepository::insert(pool, user_create, password_hash)
        .await
        .unwrap();
    let user_id = Uuid::parse_str(&inserted_user.id).unwrap();

    // Update the user
    let user_update = UserUpdate {
        username: Some("updated_username".to_string()),
        email: Some("updated@test.com".to_string()),
        password: None,
    };

    let result = UserRepository::update(pool, user_id, user_update, None).await;
    assert!(result.is_ok());

    let updated_user = result.unwrap();
    assert!(updated_user.is_some());

    let user = updated_user.unwrap();
    assert_eq!(user.username, "updated_username");
    assert_eq!(user.email, "updated@test.com");
    assert_eq!(user.id, inserted_user.id);
    assert_eq!(user.password_hash, inserted_user.password_hash); // Should remain unchanged

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_update_user_with_password() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert a user first
    let user_create = test_data::create_test_user();
    let password_hash = "hashed_password_123".to_string();
    let inserted_user = UserRepository::insert(pool, user_create, password_hash)
        .await
        .unwrap();
    let user_id = Uuid::parse_str(&inserted_user.id).unwrap();

    // Update with new password
    let user_update = UserUpdate {
        username: None,
        email: None,
        password: Some("new_password".to_string()),
    };
    let new_password_hash = "new_hashed_password_456".to_string();

    let result =
        UserRepository::update(pool, user_id, user_update, Some(new_password_hash.clone())).await;
    assert!(result.is_ok());

    let updated_user = result.unwrap();
    assert!(updated_user.is_some());

    let user = updated_user.unwrap();
    assert_eq!(user.password_hash, new_password_hash);
    assert_eq!(user.username, inserted_user.username); // Should remain unchanged
    assert_eq!(user.email, inserted_user.email); // Should remain unchanged

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_update_user_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let non_existent_id = Uuid::new_v4();
    let user_update = UserUpdate {
        username: Some("updated_username".to_string()),
        email: None,
        password: None,
    };

    let result = UserRepository::update(pool, non_existent_id, user_update, None).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_delete_user_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert a user first
    let user_create = test_data::create_test_user();
    let password_hash = "hashed_password_123".to_string();
    let inserted_user = UserRepository::insert(pool, user_create, password_hash)
        .await
        .unwrap();
    let user_id = Uuid::parse_str(&inserted_user.id).unwrap();

    // Delete the user
    let result = UserRepository::delete(pool, user_id).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Verify the user is deleted
    let find_result = UserRepository::find_by_id(pool, user_id).await;
    assert!(find_result.is_ok());
    assert!(find_result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_delete_user_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let non_existent_id = Uuid::new_v4();
    let result = UserRepository::delete(pool, non_existent_id).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_exists_by_username() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Test non-existent username
    let result = UserRepository::exists_by_username(pool, "nonexistent").await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    // Insert a user
    let user_create = test_data::create_test_user_with_data("existstest", "exists@test.com");
    let password_hash = "hashed_password_123".to_string();
    UserRepository::insert(pool, user_create, password_hash)
        .await
        .unwrap();

    // Test existing username
    let result = UserRepository::exists_by_username(pool, "existstest").await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_exists_by_email() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Test non-existent email
    let result = UserRepository::exists_by_email(pool, "nonexistent@test.com").await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    // Insert a user
    let user_create = test_data::create_test_user_with_data("emailexists", "emailexists@test.com");
    let password_hash = "hashed_password_123".to_string();
    UserRepository::insert(pool, user_create, password_hash)
        .await
        .unwrap();

    // Test existing email
    let result = UserRepository::exists_by_email(pool, "emailexists@test.com").await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_exists_by_username_excluding_id() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert two users
    let user1_create = test_data::create_test_user_with_data("user1", "user1@test.com");
    let user2_create = test_data::create_test_user_with_data("user2", "user2@test.com");
    let password_hash = "hashed_password_123".to_string();

    let user1 = UserRepository::insert(pool, user1_create, password_hash.clone())
        .await
        .unwrap();
    let user2 = UserRepository::insert(pool, user2_create, password_hash)
        .await
        .unwrap();

    let user1_id = Uuid::parse_str(&user1.id).unwrap();
    let user2_id = Uuid::parse_str(&user2.id).unwrap();

    // Check if user1's username exists excluding user1's ID (should be false)
    let result = UserRepository::exists_by_username_excluding_id(pool, "user1", user1_id).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    // Check if user1's username exists excluding user2's ID (should be true)
    let result = UserRepository::exists_by_username_excluding_id(pool, "user1", user2_id).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_exists_by_email_excluding_id() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert two users
    let user1_create = test_data::create_test_user_with_data("user1", "user1@test.com");
    let user2_create = test_data::create_test_user_with_data("user2", "user2@test.com");
    let password_hash = "hashed_password_123".to_string();

    let user1 = UserRepository::insert(pool, user1_create, password_hash.clone())
        .await
        .unwrap();
    let user2 = UserRepository::insert(pool, user2_create, password_hash)
        .await
        .unwrap();

    let user1_id = Uuid::parse_str(&user1.id).unwrap();
    let user2_id = Uuid::parse_str(&user2.id).unwrap();

    // Check if user1's email exists excluding user1's ID (should be false)
    let result =
        UserRepository::exists_by_email_excluding_id(pool, "user1@test.com", user1_id).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    // Check if user1's email exists excluding user2's ID (should be true)
    let result =
        UserRepository::exists_by_email_excluding_id(pool, "user1@test.com", user2_id).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    test_db.cleanup().await;
}
