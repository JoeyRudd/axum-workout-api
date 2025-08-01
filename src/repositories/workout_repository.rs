use sqlx::PgPool;
use uuid::Uuid;

use crate::models::workout::{Workout, WorkoutCreate, WorkoutUpdate};

pub struct WorkoutRepository;

impl WorkoutRepository {
    // Insert a new workout
    pub async fn insert(
        pool: &PgPool,
        user_id: Uuid,
        workout_create: WorkoutCreate,
    ) -> Result<Workout, sqlx::Error> {
        let id = Uuid::new_v4();
        let created_at = chrono::Utc::now();

        let workout = sqlx::query_as!(
            Workout,
            r#"
            INSERT INTO workouts (id, user_id, name, description, workout_date, duration_minutes, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, user_id, name, description, workout_date, duration_minutes, created_at, updated_at
            "#,
            id.to_string(),
            user_id.to_string(),
            workout_create.name,
            workout_create.description,
            workout_create.workout_date.to_rfc3339(),
            workout_create.duration_minutes,
            created_at.to_rfc3339()
        )
        .fetch_one(pool)
        .await?;

        Ok(workout)
    }

    // Find workout by ID
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Workout>, sqlx::Error> {
        let workout = sqlx::query_as!(
            Workout,
            "SELECT id, user_id, name, description, workout_date, duration_minutes, created_at, updated_at FROM workouts WHERE id = $1",
            id.to_string()
        )
        .fetch_optional(pool)
        .await?;

        Ok(workout)
    }

    // Find workout by ID and user ID (for authorization)
    pub async fn find_by_id_and_user(
        pool: &PgPool,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Workout>, sqlx::Error> {
        let workout = sqlx::query_as!(
            Workout,
            "SELECT id, user_id, name, description, workout_date, duration_minutes, created_at, updated_at FROM workouts WHERE id = $1 AND user_id = $2",
            id.to_string(),
            user_id.to_string()
        )
        .fetch_optional(pool)
        .await?;

        Ok(workout)
    }

    // Find all workouts for a user
    pub async fn find_by_user_id(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<Workout>, sqlx::Error> {
        let workouts = sqlx::query_as!(
            Workout,
            "SELECT id, user_id, name, description, workout_date, duration_minutes, created_at, updated_at FROM workouts WHERE user_id = $1 ORDER BY workout_date DESC",
            user_id.to_string()
        )
        .fetch_all(pool)
        .await?;

        Ok(workouts)
    }

    // Find workouts by user ID with date range
    pub async fn find_by_user_and_date_range(
        pool: &PgPool,
        user_id: Uuid,
        start_date: &str,
        end_date: &str,
    ) -> Result<Vec<Workout>, sqlx::Error> {
        let workouts = sqlx::query_as!(
            Workout,
            "SELECT id, user_id, name, description, workout_date, duration_minutes, created_at, updated_at FROM workouts WHERE user_id = $1 AND workout_date >= $2 AND workout_date <= $3 ORDER BY workout_date DESC",
            user_id.to_string(),
            start_date,
            end_date
        )
        .fetch_all(pool)
        .await?;

        Ok(workouts)
    }

    // Find recent workouts for a user (last N workouts)
    pub async fn find_recent_by_user(
        pool: &PgPool,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Workout>, sqlx::Error> {
        let workouts = sqlx::query_as!(
            Workout,
            "SELECT id, user_id, name, description, workout_date, duration_minutes, created_at, updated_at FROM workouts WHERE user_id = $1 ORDER BY workout_date DESC LIMIT $2",
            user_id.to_string(),
            limit
        )
        .fetch_all(pool)
        .await?;

        Ok(workouts)
    }

    // Search workouts by name pattern for a user
    pub async fn search_by_name_pattern(
        pool: &PgPool,
        user_id: Uuid,
        pattern: &str,
    ) -> Result<Vec<Workout>, sqlx::Error> {
        let workouts = sqlx::query_as!(
            Workout,
            "SELECT id, user_id, name, description, workout_date, duration_minutes, created_at, updated_at FROM workouts WHERE user_id = $1 AND name ILIKE $2 ORDER BY workout_date DESC",
            user_id.to_string(),
            pattern
        )
        .fetch_all(pool)
        .await?;

        Ok(workouts)
    }

    // Update workout
    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        user_id: Uuid,
        workout_update: WorkoutUpdate,
    ) -> Result<Option<Workout>, sqlx::Error> {
        let updated_at = chrono::Utc::now();

        let updated_workout = sqlx::query_as!(
            Workout,
            r#"
            UPDATE workouts
            SET
                name = COALESCE($3, name),
                description = COALESCE($4, description),
                workout_date = COALESCE($5, workout_date),
                duration_minutes = COALESCE($6, duration_minutes),
                updated_at = $7
            WHERE id = $1 AND user_id = $2
            RETURNING id, user_id, name, description, workout_date, duration_minutes, created_at, updated_at
            "#,
            id.to_string(),
            user_id.to_string(),
            workout_update.name,
            workout_update.description,
            workout_update.workout_date.map(|dt| dt.to_rfc3339()),
            workout_update.duration_minutes,
            updated_at.to_rfc3339()
        )
        .fetch_optional(pool)
        .await?;

        Ok(updated_workout)
    }

    // Delete workout
    pub async fn delete(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            "DELETE FROM workouts WHERE id = $1 AND user_id = $2",
            id.to_string(),
            user_id.to_string()
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // Get workout count for a user
    pub async fn count_by_user(pool: &PgPool, user_id: Uuid) -> Result<i64, sqlx::Error> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM workouts WHERE user_id = $1",
            user_id.to_string()
        )
        .fetch_one(pool)
        .await?;

        Ok(count.unwrap_or(0))
    }

    // Get total workout duration for a user
    pub async fn total_duration_by_user(pool: &PgPool, user_id: Uuid) -> Result<i64, sqlx::Error> {
        let total = sqlx::query_scalar!(
            "SELECT COALESCE(SUM(duration_minutes), 0) FROM workouts WHERE user_id = $1 AND duration_minutes IS NOT NULL",
            user_id.to_string()
        )
        .fetch_one(pool)
        .await?;

        Ok(total.unwrap_or(0) as i64)
    }

    // Check if workout exists by name for user (for duplicate checking)
    pub async fn exists_by_name_and_user(
        pool: &PgPool,
        name: &str,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM workouts WHERE name = $1 AND user_id = $2",
            name,
            user_id.to_string()
        )
        .fetch_one(pool)
        .await?;

        Ok(count.unwrap_or(0) > 0)
    }

    // Check if workout exists by name for user excluding specific workout ID (for updates)
    pub async fn exists_by_name_and_user_excluding_id(
        pool: &PgPool,
        name: &str,
        user_id: Uuid,
        exclude_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM workouts WHERE name = $1 AND user_id = $2 AND id != $3",
            name,
            user_id.to_string(),
            exclude_id.to_string()
        )
        .fetch_one(pool)
        .await?;

        Ok(count.unwrap_or(0) > 0)
    }
}
