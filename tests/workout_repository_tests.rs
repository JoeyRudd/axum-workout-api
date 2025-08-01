mod common;

use axum_workout_api::models::workout::{WorkoutCreate, WorkoutUpdate};
use axum_workout_api::repositories::{UserRepository, WorkoutRepository};
use chrono::{Duration, Utc};
use common::{TestDb, test_data};
use uuid::Uuid;

// Helper function to create a test user and return the UUID
async fn create_test_user(pool: &sqlx::PgPool) -> Uuid {
    let user_create = test_data::create_test_user();
    let password_hash = "hashed_password_123".to_string();
    let user = UserRepository::insert(pool, user_create, password_hash)
        .await
        .unwrap();
    Uuid::parse_str(&user.id).unwrap()
}

#[tokio::test]
async fn test_insert_workout_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;
    let workout_create = test_data::create_test_workout(user_id);

    let result = WorkoutRepository::insert(pool, user_id, workout_create.clone()).await;

    assert!(result.is_ok());
    let workout = result.unwrap();

    assert_eq!(workout.name, workout_create.name);
    assert_eq!(workout.description, workout_create.description);
    assert_eq!(
        workout.workout_date,
        workout_create.workout_date.to_rfc3339()
    );
    assert_eq!(workout.duration_minutes, workout_create.duration_minutes);
    assert_eq!(workout.user_id, user_id.to_string());
    assert!(!workout.id.is_empty());
    assert!(!workout.created_at.is_empty());
    assert!(workout.updated_at.is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_id_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;
    let workout_create = test_data::create_test_workout(user_id);
    let inserted_workout = WorkoutRepository::insert(pool, user_id, workout_create)
        .await
        .unwrap();
    let workout_id = Uuid::parse_str(&inserted_workout.id).unwrap();

    let result = WorkoutRepository::find_by_id(pool, workout_id).await;
    assert!(result.is_ok());

    let found_workout = result.unwrap();
    assert!(found_workout.is_some());

    let workout = found_workout.unwrap();
    assert_eq!(workout.id, inserted_workout.id);
    assert_eq!(workout.name, inserted_workout.name);
    assert_eq!(workout.user_id, inserted_workout.user_id);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_id_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let non_existent_id = Uuid::new_v4();
    let result = WorkoutRepository::find_by_id(pool, non_existent_id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_id_and_user_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;
    let workout_create = test_data::create_test_workout(user_id);
    let inserted_workout = WorkoutRepository::insert(pool, user_id, workout_create)
        .await
        .unwrap();
    let workout_id = Uuid::parse_str(&inserted_workout.id).unwrap();

    let result = WorkoutRepository::find_by_id_and_user(pool, workout_id, user_id).await;
    assert!(result.is_ok());

    let found_workout = result.unwrap();
    assert!(found_workout.is_some());

    let workout = found_workout.unwrap();
    assert_eq!(workout.id, inserted_workout.id);
    assert_eq!(workout.user_id, user_id.to_string());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_id_and_user_wrong_user() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user1_id = create_test_user(pool).await;
    let user2_id = create_test_user(pool).await;

    let workout_create = test_data::create_test_workout(user1_id);
    let inserted_workout = WorkoutRepository::insert(pool, user1_id, workout_create)
        .await
        .unwrap();
    let workout_id = Uuid::parse_str(&inserted_workout.id).unwrap();

    // Try to find user1's workout with user2's ID
    let result = WorkoutRepository::find_by_id_and_user(pool, workout_id, user2_id).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_user_id() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user1_id = create_test_user(pool).await;
    let user2_id = create_test_user(pool).await;

    // Insert workouts for user1
    let workout1 = test_data::create_test_workout_with_name("User1 Workout 1");
    let workout2 = test_data::create_test_workout_with_name("User1 Workout 2");
    WorkoutRepository::insert(pool, user1_id, workout1)
        .await
        .unwrap();
    WorkoutRepository::insert(pool, user1_id, workout2)
        .await
        .unwrap();

    // Insert workout for user2
    let workout3 = test_data::create_test_workout_with_name("User2 Workout 1");
    WorkoutRepository::insert(pool, user2_id, workout3)
        .await
        .unwrap();

    // Find workouts for user1
    let result = WorkoutRepository::find_by_user_id(pool, user1_id).await;
    assert!(result.is_ok());

    let user1_workouts = result.unwrap();
    assert_eq!(user1_workouts.len(), 2);

    // All workouts should belong to user1
    for workout in &user1_workouts {
        assert_eq!(workout.user_id, user1_id.to_string());
    }

    // Should be ordered by workout_date DESC
    let workout_names: Vec<String> = user1_workouts.iter().map(|w| w.name.clone()).collect();
    assert!(workout_names.contains(&"User1 Workout 1".to_string()));
    assert!(workout_names.contains(&"User1 Workout 2".to_string()));

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_user_and_date_range() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;
    let base_date = Utc::now();

    // Create workouts with different dates
    let workout1 = WorkoutCreate {
        name: "Old Workout".to_string(),
        description: Some("Old workout".to_string()),
        workout_date: base_date - Duration::days(10),
        duration_minutes: Some(30),
    };

    let workout2 = WorkoutCreate {
        name: "Recent Workout".to_string(),
        description: Some("Recent workout".to_string()),
        workout_date: base_date - Duration::days(3),
        duration_minutes: Some(45),
    };

    let workout3 = WorkoutCreate {
        name: "Future Workout".to_string(),
        description: Some("Future workout".to_string()),
        workout_date: base_date + Duration::days(5),
        duration_minutes: Some(60),
    };

    WorkoutRepository::insert(pool, user_id, workout1)
        .await
        .unwrap();
    WorkoutRepository::insert(pool, user_id, workout2)
        .await
        .unwrap();
    WorkoutRepository::insert(pool, user_id, workout3)
        .await
        .unwrap();

    // Find workouts in the last 7 days
    let start_date = (base_date - Duration::days(7)).to_rfc3339();
    let end_date = base_date.to_rfc3339();

    let result =
        WorkoutRepository::find_by_user_and_date_range(pool, user_id, &start_date, &end_date).await;
    assert!(result.is_ok());

    let workouts_in_range = result.unwrap();
    assert_eq!(workouts_in_range.len(), 1);
    assert_eq!(workouts_in_range[0].name, "Recent Workout");

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_recent_by_user() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;

    // Insert 5 workouts
    for i in 1..=5 {
        let workout = WorkoutCreate {
            name: format!("Workout {}", i),
            description: Some(format!("Workout {} description", i)),
            workout_date: Utc::now() - Duration::days(i as i64),
            duration_minutes: Some(30 + i),
        };
        WorkoutRepository::insert(pool, user_id, workout)
            .await
            .unwrap();
    }

    // Find recent 3 workouts
    let result = WorkoutRepository::find_recent_by_user(pool, user_id, 3).await;
    assert!(result.is_ok());

    let recent_workouts = result.unwrap();
    assert_eq!(recent_workouts.len(), 3);

    // Should be ordered by workout_date DESC (most recent first)
    let workout_names: Vec<String> = recent_workouts.iter().map(|w| w.name.clone()).collect();
    assert_eq!(workout_names[0], "Workout 1"); // Most recent
    assert_eq!(workout_names[1], "Workout 2");
    assert_eq!(workout_names[2], "Workout 3");

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_search_by_name_pattern() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;

    // Insert workouts with searchable names
    let workouts = vec![
        "Morning Push Workout",
        "Evening Pull Session",
        "Leg Day Workout",
        "Push-Pull-Legs",
    ];

    for name in workouts {
        let workout = test_data::create_test_workout_with_name(name);
        WorkoutRepository::insert(pool, user_id, workout)
            .await
            .unwrap();
    }

    // Search for workouts containing "Push"
    let result = WorkoutRepository::search_by_name_pattern(pool, user_id, "%Push%").await;
    assert!(result.is_ok());

    let push_workouts = result.unwrap();
    assert!(push_workouts.len() >= 2);

    let names: Vec<String> = push_workouts.iter().map(|w| w.name.clone()).collect();
    assert!(names.iter().any(|name| name.contains("Push")));

    // Search for workouts containing "Leg"
    let result = WorkoutRepository::search_by_name_pattern(pool, user_id, "%Leg%").await;
    assert!(result.is_ok());

    let leg_workouts = result.unwrap();
    assert!(leg_workouts.len() >= 1);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_update_workout_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;
    let workout_create = test_data::create_test_workout_with_name("Workout to Update");
    let inserted_workout = WorkoutRepository::insert(pool, user_id, workout_create)
        .await
        .unwrap();
    let workout_id = Uuid::parse_str(&inserted_workout.id).unwrap();

    // Update the workout
    let new_date = Utc::now() + Duration::days(1);
    let workout_update = WorkoutUpdate {
        name: Some("Updated Workout Name".to_string()),
        description: Some("Updated description".to_string()),
        workout_date: Some(new_date),
        duration_minutes: Some(90),
    };

    let result = WorkoutRepository::update(pool, workout_id, user_id, workout_update).await;
    assert!(result.is_ok());

    let updated_workout = result.unwrap();
    assert!(updated_workout.is_some());

    let workout = updated_workout.unwrap();
    assert_eq!(workout.name, "Updated Workout Name");
    assert_eq!(workout.description, Some("Updated description".to_string()));
    assert_eq!(workout.workout_date, new_date.to_rfc3339());
    assert_eq!(workout.duration_minutes, Some(90));
    assert_eq!(workout.id, inserted_workout.id);
    assert!(workout.updated_at.is_some());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_update_workout_partial() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;
    let workout_create = test_data::create_test_workout_with_name("Partial Update Workout");
    let inserted_workout = WorkoutRepository::insert(pool, user_id, workout_create)
        .await
        .unwrap();
    let workout_id = Uuid::parse_str(&inserted_workout.id).unwrap();

    // Update only the name
    let workout_update = WorkoutUpdate {
        name: Some("Partially Updated Workout".to_string()),
        description: None,
        workout_date: None,
        duration_minutes: None,
    };

    let result = WorkoutRepository::update(pool, workout_id, user_id, workout_update).await;
    assert!(result.is_ok());

    let updated_workout = result.unwrap();
    assert!(updated_workout.is_some());

    let workout = updated_workout.unwrap();
    assert_eq!(workout.name, "Partially Updated Workout");
    // Other fields should remain unchanged
    assert_eq!(workout.description, inserted_workout.description);
    assert_eq!(workout.workout_date, inserted_workout.workout_date);
    assert_eq!(workout.duration_minutes, inserted_workout.duration_minutes);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_update_workout_wrong_user() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user1_id = create_test_user(pool).await;
    let user2_id = create_test_user(pool).await;

    let workout_create = test_data::create_test_workout_with_name("User1's Workout");
    let inserted_workout = WorkoutRepository::insert(pool, user1_id, workout_create)
        .await
        .unwrap();
    let workout_id = Uuid::parse_str(&inserted_workout.id).unwrap();

    // Try to update user1's workout as user2
    let workout_update = WorkoutUpdate {
        name: Some("Hacked Workout".to_string()),
        description: None,
        workout_date: None,
        duration_minutes: None,
    };

    let result = WorkoutRepository::update(pool, workout_id, user2_id, workout_update).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_delete_workout_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;
    let workout_create = test_data::create_test_workout_with_name("Workout to Delete");
    let inserted_workout = WorkoutRepository::insert(pool, user_id, workout_create)
        .await
        .unwrap();
    let workout_id = Uuid::parse_str(&inserted_workout.id).unwrap();

    // Delete the workout
    let result = WorkoutRepository::delete(pool, workout_id, user_id).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Verify the workout is deleted
    let find_result = WorkoutRepository::find_by_id(pool, workout_id).await;
    assert!(find_result.is_ok());
    assert!(find_result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_delete_workout_wrong_user() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user1_id = create_test_user(pool).await;
    let user2_id = create_test_user(pool).await;

    let workout_create = test_data::create_test_workout_with_name("User1's Workout");
    let inserted_workout = WorkoutRepository::insert(pool, user1_id, workout_create)
        .await
        .unwrap();
    let workout_id = Uuid::parse_str(&inserted_workout.id).unwrap();

    // Try to delete user1's workout as user2
    let result = WorkoutRepository::delete(pool, workout_id, user2_id).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    // Verify the workout still exists
    let find_result = WorkoutRepository::find_by_id(pool, workout_id).await;
    assert!(find_result.is_ok());
    assert!(find_result.unwrap().is_some());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_count_by_user() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user1_id = create_test_user(pool).await;
    let user2_id = create_test_user(pool).await;

    // Insert workouts for user1
    for i in 1..=3 {
        let workout = test_data::create_test_workout_with_name(&format!("User1 Workout {}", i));
        WorkoutRepository::insert(pool, user1_id, workout)
            .await
            .unwrap();
    }

    // Insert workouts for user2
    for i in 1..=2 {
        let workout = test_data::create_test_workout_with_name(&format!("User2 Workout {}", i));
        WorkoutRepository::insert(pool, user2_id, workout)
            .await
            .unwrap();
    }

    // Count workouts for user1
    let result = WorkoutRepository::count_by_user(pool, user1_id).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 3);

    // Count workouts for user2
    let result = WorkoutRepository::count_by_user(pool, user2_id).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 2);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_total_duration_by_user() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;

    // Insert workouts with different durations
    let workouts = vec![(30, "Workout 1"), (45, "Workout 2"), (60, "Workout 3")];

    for (duration, name) in workouts {
        let workout = WorkoutCreate {
            name: name.to_string(),
            description: Some("Test workout".to_string()),
            workout_date: Utc::now(),
            duration_minutes: Some(duration),
        };
        WorkoutRepository::insert(pool, user_id, workout)
            .await
            .unwrap();
    }

    // Insert a workout without duration (should be ignored in total)
    let workout_no_duration = WorkoutCreate {
        name: "No Duration Workout".to_string(),
        description: Some("Test workout".to_string()),
        workout_date: Utc::now(),
        duration_minutes: None,
    };
    WorkoutRepository::insert(pool, user_id, workout_no_duration)
        .await
        .unwrap();

    // Get total duration
    let result = WorkoutRepository::total_duration_by_user(pool, user_id).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 135); // 30 + 45 + 60

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_exists_by_name_and_user() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;

    // Test non-existent workout name
    let result =
        WorkoutRepository::exists_by_name_and_user(pool, "Nonexistent Workout", user_id).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    // Insert a workout
    let workout_create = test_data::create_test_workout_with_name("Existence Test Workout");
    WorkoutRepository::insert(pool, user_id, workout_create)
        .await
        .unwrap();

    // Test existing workout name
    let result =
        WorkoutRepository::exists_by_name_and_user(pool, "Existence Test Workout", user_id).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_exists_by_name_and_user_excluding_id() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;

    // Insert two workouts
    let workout1_create = test_data::create_test_workout_with_name("Workout 1");
    let workout2_create = test_data::create_test_workout_with_name("Workout 2");

    let workout1 = WorkoutRepository::insert(pool, user_id, workout1_create)
        .await
        .unwrap();
    let workout2 = WorkoutRepository::insert(pool, user_id, workout2_create)
        .await
        .unwrap();

    let workout1_id = Uuid::parse_str(&workout1.id).unwrap();
    let workout2_id = Uuid::parse_str(&workout2.id).unwrap();

    // Check if workout1's name exists excluding workout1's ID (should be false)
    let result = WorkoutRepository::exists_by_name_and_user_excluding_id(
        pool,
        "Workout 1",
        user_id,
        workout1_id,
    )
    .await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    // Check if workout1's name exists excluding workout2's ID (should be true)
    let result = WorkoutRepository::exists_by_name_and_user_excluding_id(
        pool,
        "Workout 1",
        user_id,
        workout2_id,
    )
    .await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_workout_cascading_delete() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let user_id = create_test_user(pool).await;

    // Insert a workout for the user
    let workout_create = test_data::create_test_workout_with_name("Cascade Test Workout");
    let inserted_workout = WorkoutRepository::insert(pool, user_id, workout_create)
        .await
        .unwrap();
    let workout_id = Uuid::parse_str(&inserted_workout.id).unwrap();

    // Verify the workout exists
    let find_result = WorkoutRepository::find_by_id(pool, workout_id).await;
    assert!(find_result.is_ok());
    assert!(find_result.unwrap().is_some());

    // Delete the user (should cascade delete the workout)
    let delete_user_result = UserRepository::delete(pool, user_id).await;
    assert!(delete_user_result.is_ok());
    assert!(delete_user_result.unwrap());

    // Verify the workout is also deleted due to cascade
    let find_result = WorkoutRepository::find_by_id(pool, workout_id).await;
    assert!(find_result.is_ok());
    assert!(find_result.unwrap().is_none());

    test_db.cleanup().await;
}
