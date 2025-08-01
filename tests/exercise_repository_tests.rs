mod common;

use axum_workout_api::models::exercise::{ExerciseCreate, ExerciseUpdate};
use axum_workout_api::repositories::ExerciseRepository;
use common::{TestDb, test_data};
use uuid::Uuid;

#[tokio::test]
async fn test_insert_exercise_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let exercise_create = test_data::create_test_exercise();

    let result = ExerciseRepository::insert(pool, exercise_create.clone()).await;

    assert!(result.is_ok());
    let exercise = result.unwrap();

    assert_eq!(exercise.name, exercise_create.name);
    assert_eq!(exercise.description, exercise_create.description);
    assert_eq!(exercise.muscle_groups.0, exercise_create.muscle_groups);
    assert_eq!(exercise.equipment_needed, exercise_create.equipment_needed);
    assert_eq!(exercise.exercise_type, exercise_create.exercise_type);
    assert_eq!(exercise.instructions, exercise_create.instructions);
    assert!(!exercise.id.is_empty());
    assert!(!exercise.created_at.is_empty());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_insert_exercise_duplicate_name() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let exercise_create = test_data::create_test_exercise_with_name("Duplicate Exercise");

    // Insert first exercise
    let result1 = ExerciseRepository::insert(pool, exercise_create.clone()).await;
    assert!(result1.is_ok());

    // Try to insert exercise with same name
    let result2 = ExerciseRepository::insert(pool, exercise_create).await;
    assert!(result2.is_err());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_id_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert an exercise first
    let exercise_create = test_data::create_test_exercise();
    let inserted_exercise = ExerciseRepository::insert(pool, exercise_create)
        .await
        .unwrap();
    let exercise_id = Uuid::parse_str(&inserted_exercise.id).unwrap();

    // Find the exercise by ID
    let result = ExerciseRepository::find_by_id(pool, exercise_id).await;
    assert!(result.is_ok());

    let found_exercise = result.unwrap();
    assert!(found_exercise.is_some());

    let exercise = found_exercise.unwrap();
    assert_eq!(exercise.id, inserted_exercise.id);
    assert_eq!(exercise.name, inserted_exercise.name);
    assert_eq!(exercise.description, inserted_exercise.description);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_id_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let non_existent_id = Uuid::new_v4();
    let result = ExerciseRepository::find_by_id(pool, non_existent_id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_name_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert an exercise first
    let exercise_create = test_data::create_test_exercise_with_name("Unique Exercise Name");
    let inserted_exercise = ExerciseRepository::insert(pool, exercise_create)
        .await
        .unwrap();

    // Find the exercise by name
    let result = ExerciseRepository::find_by_name(pool, "Unique Exercise Name").await;
    assert!(result.is_ok());

    let found_exercise = result.unwrap();
    assert!(found_exercise.is_some());

    let exercise = found_exercise.unwrap();
    assert_eq!(exercise.name, "Unique Exercise Name");
    assert_eq!(exercise.id, inserted_exercise.id);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_name_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let result = ExerciseRepository::find_by_name(pool, "Nonexistent Exercise").await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_all_exercises() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // The database already has sample exercises from migrations
    // Insert additional exercises to test
    let exercise1 = test_data::create_test_exercise_with_name("Test Exercise A");
    let exercise2 = test_data::create_test_exercise_with_name("Test Exercise B");
    let exercise3 = test_data::create_test_exercise_with_name("Test Exercise C");

    ExerciseRepository::insert(pool, exercise1).await.unwrap();
    ExerciseRepository::insert(pool, exercise2).await.unwrap();
    ExerciseRepository::insert(pool, exercise3).await.unwrap();

    // Find all exercises
    let result = ExerciseRepository::find_all(pool).await;
    assert!(result.is_ok());

    let exercises = result.unwrap();
    // Should have at least our 3 test exercises plus the sample ones from migrations
    assert!(exercises.len() >= 3);

    // Check that our test exercises are included
    let exercise_names: Vec<String> = exercises.iter().map(|e| e.name.clone()).collect();
    assert!(exercise_names.contains(&"Test Exercise A".to_string()));
    assert!(exercise_names.contains(&"Test Exercise B".to_string()));
    assert!(exercise_names.contains(&"Test Exercise C".to_string()));

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_type() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert exercises with different types
    let strength_exercise = ExerciseCreate {
        name: "Strength Test Exercise".to_string(),
        description: Some("A strength exercise".to_string()),
        muscle_groups: vec!["chest".to_string()],
        equipment_needed: None,
        exercise_type: "strength".to_string(),
        instructions: None,
    };

    let cardio_exercise = ExerciseCreate {
        name: "Cardio Test Exercise".to_string(),
        description: Some("A cardio exercise".to_string()),
        muscle_groups: vec!["cardiovascular".to_string()],
        equipment_needed: None,
        exercise_type: "cardio".to_string(),
        instructions: None,
    };

    ExerciseRepository::insert(pool, strength_exercise)
        .await
        .unwrap();
    ExerciseRepository::insert(pool, cardio_exercise)
        .await
        .unwrap();

    // Find strength exercises
    let result = ExerciseRepository::find_by_type(pool, "strength").await;
    assert!(result.is_ok());

    let strength_exercises = result.unwrap();
    assert!(strength_exercises.len() >= 1);

    // All returned exercises should be strength type
    for exercise in &strength_exercises {
        assert_eq!(exercise.exercise_type, "strength");
    }

    // Find cardio exercises
    let result = ExerciseRepository::find_by_type(pool, "cardio").await;
    assert!(result.is_ok());

    let cardio_exercises = result.unwrap();
    assert!(cardio_exercises.len() >= 1);

    // All returned exercises should be cardio type
    for exercise in &cardio_exercises {
        assert_eq!(exercise.exercise_type, "cardio");
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_find_by_muscle_group() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert exercises with specific muscle groups
    let chest_exercise = ExerciseCreate {
        name: "Chest Exercise Test".to_string(),
        description: Some("Targets chest".to_string()),
        muscle_groups: vec!["chest".to_string(), "triceps".to_string()],
        equipment_needed: None,
        exercise_type: "strength".to_string(),
        instructions: None,
    };

    let leg_exercise = ExerciseCreate {
        name: "Leg Exercise Test".to_string(),
        description: Some("Targets legs".to_string()),
        muscle_groups: vec!["quadriceps".to_string(), "glutes".to_string()],
        equipment_needed: None,
        exercise_type: "strength".to_string(),
        instructions: None,
    };

    ExerciseRepository::insert(pool, chest_exercise)
        .await
        .unwrap();
    ExerciseRepository::insert(pool, leg_exercise)
        .await
        .unwrap();

    // Find exercises targeting chest
    let result = ExerciseRepository::find_by_muscle_group(pool, "chest").await;
    assert!(result.is_ok());

    let chest_exercises = result.unwrap();
    assert!(chest_exercises.len() >= 1);

    // All returned exercises should target chest
    for exercise in &chest_exercises {
        assert!(exercise.muscle_groups.0.contains(&"chest".to_string()));
    }

    // Find exercises targeting quadriceps
    let result = ExerciseRepository::find_by_muscle_group(pool, "quadriceps").await;
    assert!(result.is_ok());

    let quad_exercises = result.unwrap();
    assert!(quad_exercises.len() >= 1);

    // All returned exercises should target quadriceps
    for exercise in &quad_exercises {
        assert!(exercise.muscle_groups.0.contains(&"quadriceps".to_string()));
    }

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_search_by_name_pattern() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert exercises with searchable names
    let exercises = vec![
        "Push-up Variation",
        "Pull-up Variation",
        "Squat Variation",
        "Deadlift Variation",
    ];

    for name in exercises {
        let exercise = test_data::create_test_exercise_with_name(name);
        ExerciseRepository::insert(pool, exercise).await.unwrap();
    }

    // Search for exercises containing "up"
    let result = ExerciseRepository::search_by_name_pattern(pool, "%up%").await;
    assert!(result.is_ok());

    let up_exercises = result.unwrap();
    assert!(up_exercises.len() >= 2); // Should find "Push-up" and "Pull-up"

    let names: Vec<String> = up_exercises.iter().map(|e| e.name.clone()).collect();
    assert!(names.iter().any(|name| name.contains("Push-up")));
    assert!(names.iter().any(|name| name.contains("Pull-up")));

    // Search for exercises containing "Variation"
    let result = ExerciseRepository::search_by_name_pattern(pool, "%Variation%").await;
    assert!(result.is_ok());

    let variation_exercises = result.unwrap();
    assert!(variation_exercises.len() >= 4); // Should find all our test exercises

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_update_exercise_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert an exercise first
    let exercise_create = test_data::create_test_exercise_with_name("Exercise to Update");
    let inserted_exercise = ExerciseRepository::insert(pool, exercise_create)
        .await
        .unwrap();
    let exercise_id = Uuid::parse_str(&inserted_exercise.id).unwrap();

    // Update the exercise
    let exercise_update = ExerciseUpdate {
        name: Some("Updated Exercise Name".to_string()),
        description: Some("Updated description".to_string()),
        muscle_groups: Some(vec!["shoulders".to_string(), "back".to_string()]),
        equipment_needed: Some("resistance bands".to_string()),
        exercise_type: Some("flexibility".to_string()),
        instructions: Some("Updated instructions".to_string()),
    };

    let result = ExerciseRepository::update(pool, exercise_id, exercise_update).await;
    assert!(result.is_ok());

    let updated_exercise = result.unwrap();
    assert!(updated_exercise.is_some());

    let exercise = updated_exercise.unwrap();
    assert_eq!(exercise.name, "Updated Exercise Name");
    assert_eq!(
        exercise.description,
        Some("Updated description".to_string())
    );
    assert_eq!(
        exercise.muscle_groups.0,
        vec!["shoulders".to_string(), "back".to_string()]
    );
    assert_eq!(
        exercise.equipment_needed,
        Some("resistance bands".to_string())
    );
    assert_eq!(exercise.exercise_type, "flexibility");
    assert_eq!(
        exercise.instructions,
        Some("Updated instructions".to_string())
    );
    assert_eq!(exercise.id, inserted_exercise.id);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_update_exercise_partial() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert an exercise first
    let exercise_create = test_data::create_test_exercise_with_name("Partial Update Exercise");
    let inserted_exercise = ExerciseRepository::insert(pool, exercise_create)
        .await
        .unwrap();
    let exercise_id = Uuid::parse_str(&inserted_exercise.id).unwrap();

    // Update only the name
    let exercise_update = ExerciseUpdate {
        name: Some("Partially Updated Exercise".to_string()),
        description: None,
        muscle_groups: None,
        equipment_needed: None,
        exercise_type: None,
        instructions: None,
    };

    let result = ExerciseRepository::update(pool, exercise_id, exercise_update).await;
    assert!(result.is_ok());

    let updated_exercise = result.unwrap();
    assert!(updated_exercise.is_some());

    let exercise = updated_exercise.unwrap();
    assert_eq!(exercise.name, "Partially Updated Exercise");
    // Other fields should remain unchanged
    assert_eq!(exercise.description, inserted_exercise.description);
    assert_eq!(exercise.muscle_groups.0, inserted_exercise.muscle_groups.0);
    assert_eq!(
        exercise.equipment_needed,
        inserted_exercise.equipment_needed
    );
    assert_eq!(exercise.exercise_type, inserted_exercise.exercise_type);
    assert_eq!(exercise.instructions, inserted_exercise.instructions);

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_update_exercise_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let non_existent_id = Uuid::new_v4();
    let exercise_update = ExerciseUpdate {
        name: Some("Updated Name".to_string()),
        description: None,
        muscle_groups: None,
        equipment_needed: None,
        exercise_type: None,
        instructions: None,
    };

    let result = ExerciseRepository::update(pool, non_existent_id, exercise_update).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_delete_exercise_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Insert an exercise first
    let exercise_create = test_data::create_test_exercise_with_name("Exercise to Delete");
    let inserted_exercise = ExerciseRepository::insert(pool, exercise_create)
        .await
        .unwrap();
    let exercise_id = Uuid::parse_str(&inserted_exercise.id).unwrap();

    // Delete the exercise
    let result = ExerciseRepository::delete(pool, exercise_id).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Verify the exercise is deleted
    let find_result = ExerciseRepository::find_by_id(pool, exercise_id).await;
    assert!(find_result.is_ok());
    assert!(find_result.unwrap().is_none());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_delete_exercise_not_found() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    let non_existent_id = Uuid::new_v4();
    let result = ExerciseRepository::delete(pool, non_existent_id).await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_exists_by_name() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Test non-existent exercise name
    let result = ExerciseRepository::exists_by_name(pool, "Nonexistent Exercise").await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    // Insert an exercise
    let exercise_create = test_data::create_test_exercise_with_name("Existence Test Exercise");
    ExerciseRepository::insert(pool, exercise_create)
        .await
        .unwrap();

    // Test existing exercise name
    let result = ExerciseRepository::exists_by_name(pool, "Existence Test Exercise").await;
    assert!(result.is_ok());
    assert!(result.unwrap());

    test_db.cleanup().await;
}

#[tokio::test]
async fn test_exercise_type_validation() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Test valid exercise types
    let valid_types = vec!["strength", "cardio", "flexibility", "balance", "sports"];

    for exercise_type in valid_types {
        let exercise_create = ExerciseCreate {
            name: format!("Test {} Exercise", exercise_type),
            description: Some("Test exercise".to_string()),
            muscle_groups: vec!["test".to_string()],
            equipment_needed: None,
            exercise_type: exercise_type.to_string(),
            instructions: None,
        };

        let result = ExerciseRepository::insert(pool, exercise_create).await;
        assert!(
            result.is_ok(),
            "Failed to insert exercise with type: {}",
            exercise_type
        );
    }

    // Test invalid exercise type - this should fail due to database constraint
    let invalid_exercise = ExerciseCreate {
        name: "Invalid Type Exercise".to_string(),
        description: Some("Test exercise".to_string()),
        muscle_groups: vec!["test".to_string()],
        equipment_needed: None,
        exercise_type: "invalid_type".to_string(),
        instructions: None,
    };

    let result = ExerciseRepository::insert(pool, invalid_exercise).await;
    assert!(
        result.is_err(),
        "Should have failed with invalid exercise type"
    );

    test_db.cleanup().await;
}
