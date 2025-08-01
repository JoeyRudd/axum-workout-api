use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// Core Exercise model - pure data only
#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct Exercise {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub muscle_groups: sqlx::types::Json<Vec<String>>,
    pub equipment_needed: Option<String>,
    pub exercise_type: String,
    pub instructions: Option<String>,
    pub created_at: String,
}

// Input struct for creating exercises
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExerciseCreate {
    pub name: String,
    pub description: Option<String>,
    pub muscle_groups: Vec<String>,
    pub equipment_needed: Option<String>,
    pub exercise_type: String,
    pub instructions: Option<String>,
}

// Input struct for updating exercises
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExerciseUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub muscle_groups: Option<Vec<String>>,
    pub equipment_needed: Option<String>,
    pub exercise_type: Option<String>,
    pub instructions: Option<String>,
}

// Response struct for API responses
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExerciseResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub muscle_groups: Vec<String>,
    pub equipment_needed: Option<String>,
    pub exercise_type: String,
    pub instructions: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// Type conversion from database model to API response
impl TryFrom<Exercise> for ExerciseResponse {
    type Error = Box<dyn std::error::Error>;

    fn try_from(exercise: Exercise) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Uuid::parse_str(&exercise.id)?,
            name: exercise.name,
            description: exercise.description,
            muscle_groups: exercise.muscle_groups.0,
            equipment_needed: exercise.equipment_needed,
            exercise_type: exercise.exercise_type,
            instructions: exercise.instructions,
            created_at: chrono::DateTime::parse_from_rfc3339(&exercise.created_at)?
                .with_timezone(&chrono::Utc),
        })
    }
}
