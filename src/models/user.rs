use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// Core User model - pure data only
#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: String,
}

// Input struct for creating users
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserCreate {
    pub username: String,
    pub email: String,
    pub password: String,
}

// Input struct for updating users
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserUpdate {
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
}

// Response struct for API responses (excludes password_hash)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// Login request struct
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserLogin {
    pub username: String,
    pub password: String,
}

// Type conversion from database model to API response
impl TryFrom<User> for UserResponse {
    type Error = Box<dyn std::error::Error>;

    fn try_from(user: User) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Uuid::parse_str(&user.id)?,
            username: user.username,
            email: user.email,
            created_at: chrono::DateTime::parse_from_rfc3339(&user.created_at)?
                .with_timezone(&chrono::Utc),
        })
    }
}
