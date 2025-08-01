use sqlx::{PgPool, Postgres, migrate::MigrateDatabase};
use std::env;
use uuid::Uuid;

pub struct TestDb {
    pub pool: PgPool,
    pub db_name: String,
}

impl TestDb {
    pub async fn new() -> Self {
        // Generate a unique database name for this test
        let db_name = format!(
            "test_workout_db_{}",
            Uuid::new_v4().to_string().replace('-', "_")
        );

        // Get the base database URL from environment or use default
        let base_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost".to_string());

        // Create the test database URL
        let test_db_url = format!("{}/{}", base_url, db_name);

        // Create the test database
        if !Postgres::database_exists(&test_db_url)
            .await
            .unwrap_or(false)
        {
            Postgres::create_database(&test_db_url).await.unwrap();
        }

        // Connect to the test database
        let pool = PgPool::connect(&test_db_url).await.unwrap();

        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        Self { pool, db_name }
    }

    pub async fn cleanup(self) {
        // Close the pool
        self.pool.close().await;

        // Drop the test database
        let base_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost".to_string());
        let test_db_url = format!("{}/{}", base_url, self.db_name);

        if Postgres::database_exists(&test_db_url)
            .await
            .unwrap_or(false)
        {
            Postgres::drop_database(&test_db_url).await.unwrap();
        }
    }
}

// Helper functions for creating test data
pub mod test_data {
    use chrono::Utc;
    use uuid::Uuid;

    use axum_workout_api::models::exercise::ExerciseCreate;
    use axum_workout_api::models::user::UserCreate;
    use axum_workout_api::models::workout::WorkoutCreate;

    pub fn create_test_user() -> UserCreate {
        UserCreate {
            username: format!("testuser_{}", Uuid::new_v4().to_string()[..8].to_string()),
            email: format!(
                "test_{}@example.com",
                Uuid::new_v4().to_string()[..8].to_string()
            ),
            password: "TestPassword123".to_string(),
        }
    }

    pub fn create_test_user_with_data(username: &str, email: &str) -> UserCreate {
        UserCreate {
            username: username.to_string(),
            email: email.to_string(),
            password: "TestPassword123".to_string(),
        }
    }

    pub fn create_test_exercise() -> ExerciseCreate {
        ExerciseCreate {
            name: format!(
                "Test Exercise {}",
                Uuid::new_v4().to_string()[..8].to_string()
            ),
            description: Some("A test exercise description".to_string()),
            muscle_groups: vec!["chest".to_string(), "triceps".to_string()],
            equipment_needed: Some("dumbbells".to_string()),
            exercise_type: "strength".to_string(),
            instructions: Some("Perform the exercise slowly and with control".to_string()),
        }
    }

    pub fn create_test_exercise_with_name(name: &str) -> ExerciseCreate {
        ExerciseCreate {
            name: name.to_string(),
            description: Some("A test exercise description".to_string()),
            muscle_groups: vec!["chest".to_string(), "triceps".to_string()],
            equipment_needed: Some("dumbbells".to_string()),
            exercise_type: "strength".to_string(),
            instructions: Some("Perform the exercise slowly and with control".to_string()),
        }
    }

    pub fn create_test_workout(_user_id: uuid::Uuid) -> WorkoutCreate {
        WorkoutCreate {
            name: format!(
                "Test Workout {}",
                Uuid::new_v4().to_string()[..8].to_string()
            ),
            description: Some("A test workout description".to_string()),
            workout_date: Utc::now(),
            duration_minutes: Some(45),
        }
    }

    pub fn create_test_workout_with_name(name: &str) -> WorkoutCreate {
        WorkoutCreate {
            name: name.to_string(),
            description: Some("A test workout description".to_string()),
            workout_date: Utc::now(),
            duration_minutes: Some(45),
        }
    }
}
