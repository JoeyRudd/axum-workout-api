use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// Core Workout model - pure data only
#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct Workout {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub workout_date: String,
    pub duration_minutes: Option<i32>,
    pub created_at: String,
    pub updated_at: Option<String>,
}

// Input struct for creating workouts
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkoutCreate {
    pub name: String,
    pub description: Option<String>,
    pub workout_date: chrono::DateTime<chrono::Utc>,
    pub duration_minutes: Option<i32>,
}

// Input struct for updating workouts
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkoutUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub workout_date: Option<chrono::DateTime<chrono::Utc>>,
    pub duration_minutes: Option<i32>,
}

// Response struct for API responses
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkoutResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub workout_date: chrono::DateTime<chrono::Utc>,
    pub duration_minutes: Option<i32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

// Type conversion from database model to API response
impl TryFrom<Workout> for WorkoutResponse {
    type Error = Box<dyn std::error::Error>;

    fn try_from(workout: Workout) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Uuid::parse_str(&workout.id)?,
            user_id: Uuid::parse_str(&workout.user_id)?,
            name: workout.name,
            description: workout.description,
            workout_date: chrono::DateTime::parse_from_rfc3339(&workout.workout_date)?
                .with_timezone(&chrono::Utc),
            duration_minutes: workout.duration_minutes,
            created_at: chrono::DateTime::parse_from_rfc3339(&workout.created_at)?
                .with_timezone(&chrono::Utc),
            updated_at: workout
                .updated_at
                .map(|dt| chrono::DateTime::parse_from_rfc3339(&dt))
                .transpose()?
                .map(|dt| dt.with_timezone(&chrono::Utc)),
        })
    }
}
