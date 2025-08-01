use sqlx::PgPool;
use uuid::Uuid;

use crate::models::exercise::{Exercise, ExerciseCreate, ExerciseUpdate};

pub struct ExerciseRepository;

impl ExerciseRepository {
    // Insert a new exercise
    pub async fn insert(
        pool: &PgPool,
        exercise_create: ExerciseCreate,
    ) -> Result<Exercise, sqlx::Error> {
        let id = Uuid::new_v4();
        let created_at = chrono::Utc::now();

        let exercise = sqlx::query_as!(
            Exercise,
            r#"
            INSERT INTO exercises (id, name, description, muscle_groups, equipment_needed, exercise_type, instructions, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, name, description, muscle_groups as "muscle_groups: sqlx::types::Json<Vec<String>>", equipment_needed, exercise_type, instructions, created_at
            "#,
            id.to_string(),
            exercise_create.name,
            exercise_create.description,
            sqlx::types::Json(exercise_create.muscle_groups) as sqlx::types::Json<Vec<String>>,
            exercise_create.equipment_needed,
            exercise_create.exercise_type,
            exercise_create.instructions,
            created_at.to_rfc3339()
        )
        .fetch_one(pool)
        .await?;

        Ok(exercise)
    }

    // Find exercise by ID
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Exercise>, sqlx::Error> {
        let exercise = sqlx::query_as!(
            Exercise,
            r#"SELECT id, name, description, muscle_groups as "muscle_groups: sqlx::types::Json<Vec<String>>", equipment_needed, exercise_type, instructions, created_at FROM exercises WHERE id = $1"#,
            id.to_string()
        )
        .fetch_optional(pool)
        .await?;

        Ok(exercise)
    }

    // Find exercise by name
    pub async fn find_by_name(pool: &PgPool, name: &str) -> Result<Option<Exercise>, sqlx::Error> {
        let exercise = sqlx::query_as!(
            Exercise,
            r#"SELECT id, name, description, muscle_groups as "muscle_groups: sqlx::types::Json<Vec<String>>", equipment_needed, exercise_type, instructions, created_at FROM exercises WHERE name = $1"#,
            name
        )
        .fetch_optional(pool)
        .await?;

        Ok(exercise)
    }

    // Find all exercises
    pub async fn find_all(pool: &PgPool) -> Result<Vec<Exercise>, sqlx::Error> {
        let exercises = sqlx::query_as!(
            Exercise,
            r#"SELECT id, name, description, muscle_groups as "muscle_groups: sqlx::types::Json<Vec<String>>", equipment_needed, exercise_type, instructions, created_at FROM exercises ORDER BY name"#
        )
        .fetch_all(pool)
        .await?;

        Ok(exercises)
    }

    // Find exercises by type
    pub async fn find_by_type(
        pool: &PgPool,
        exercise_type: &str,
    ) -> Result<Vec<Exercise>, sqlx::Error> {
        let exercises = sqlx::query_as!(
            Exercise,
            r#"SELECT id, name, description, muscle_groups as "muscle_groups: sqlx::types::Json<Vec<String>>", equipment_needed, exercise_type, instructions, created_at FROM exercises WHERE exercise_type = $1 ORDER BY name"#,
            exercise_type
        )
        .fetch_all(pool)
        .await?;

        Ok(exercises)
    }

    // Find exercises by muscle group
    pub async fn find_by_muscle_group(
        pool: &PgPool,
        muscle_group: &str,
    ) -> Result<Vec<Exercise>, sqlx::Error> {
        let exercises = sqlx::query_as!(
            Exercise,
            r#"SELECT id, name, description, muscle_groups as "muscle_groups: sqlx::types::Json<Vec<String>>", equipment_needed, exercise_type, instructions, created_at FROM exercises WHERE muscle_groups ? $1 ORDER BY name"#,
            muscle_group
        )
        .fetch_all(pool)
        .await?;

        Ok(exercises)
    }

    // Search exercises by name pattern
    pub async fn search_by_name_pattern(
        pool: &PgPool,
        pattern: &str,
    ) -> Result<Vec<Exercise>, sqlx::Error> {
        let exercises = sqlx::query_as!(
            Exercise,
            r#"SELECT id, name, description, muscle_groups as "muscle_groups: sqlx::types::Json<Vec<String>>", equipment_needed, exercise_type, instructions, created_at FROM exercises WHERE name ILIKE $1 ORDER BY name"#,
            pattern
        )
        .fetch_all(pool)
        .await?;

        Ok(exercises)
    }

    // Update exercise
    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        exercise_update: ExerciseUpdate,
    ) -> Result<Option<Exercise>, sqlx::Error> {
        let updated_exercise = sqlx::query_as!(
            Exercise,
            r#"
            UPDATE exercises
            SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                muscle_groups = COALESCE($4, muscle_groups),
                equipment_needed = COALESCE($5, equipment_needed),
                exercise_type = COALESCE($6, exercise_type),
                instructions = COALESCE($7, instructions)
            WHERE id = $1
            RETURNING id, name, description, muscle_groups as "muscle_groups: sqlx::types::Json<Vec<String>>", equipment_needed, exercise_type, instructions, created_at
            "#,
            id.to_string(),
            exercise_update.name,
            exercise_update.description,
            exercise_update.muscle_groups.map(|mg| sqlx::types::Json(mg)) as Option<sqlx::types::Json<Vec<String>>>,
            exercise_update.equipment_needed,
            exercise_update.exercise_type,
            exercise_update.instructions
        )
        .fetch_optional(pool)
        .await?;

        Ok(updated_exercise)
    }

    // Delete exercise
    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!("DELETE FROM exercises WHERE id = $1", id.to_string())
            .execute(pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    // Check if exercise exists by name (for duplicate checking)
    pub async fn exists_by_name(pool: &PgPool, name: &str) -> Result<bool, sqlx::Error> {
        let count = sqlx::query_scalar!("SELECT COUNT(*) FROM exercises WHERE name = $1", name)
            .fetch_one(pool)
            .await?;

        Ok(count.unwrap_or(0) > 0)
    }
}
