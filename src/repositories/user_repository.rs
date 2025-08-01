use sqlx::PgPool;
use uuid::Uuid;

use crate::models::user::{User, UserCreate, UserUpdate};

pub struct UserRepository;

impl UserRepository {
    // Insert a new user
    pub async fn insert(
        pool: &PgPool,
        user_create: UserCreate,
        password_hash: String,
    ) -> Result<User, sqlx::Error> {
        let id = Uuid::new_v4();
        let created_at = chrono::Utc::now();

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, username, email, password_hash, created_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, username, email, password_hash, created_at
            "#,
            id.to_string(),
            user_create.username,
            user_create.email,
            password_hash,
            created_at.to_rfc3339()
        )
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

    // Find user by ID
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, username, email, password_hash, created_at FROM users WHERE id = $1",
            id.to_string()
        )
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    // Find user by username
    pub async fn find_by_username(
        pool: &PgPool,
        username: &str,
    ) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, username, email, password_hash, created_at FROM users WHERE username = $1",
            username
        )
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    // Find user by email
    pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, username, email, password_hash, created_at FROM users WHERE email = $1",
            email
        )
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    // Find all users
    pub async fn find_all(pool: &PgPool) -> Result<Vec<User>, sqlx::Error> {
        let users = sqlx::query_as!(
            User,
            "SELECT id, username, email, password_hash, created_at FROM users ORDER BY created_at DESC"
        )
        .fetch_all(pool)
        .await?;

        Ok(users)
    }

    // Update user
    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        user_update: UserUpdate,
        password_hash: Option<String>,
    ) -> Result<Option<User>, sqlx::Error> {
        let updated_user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET
                username = COALESCE($2, username),
                email = COALESCE($3, email),
                password_hash = COALESCE($4, password_hash)
            WHERE id = $1
            RETURNING id, username, email, password_hash, created_at
            "#,
            id.to_string(),
            user_update.username,
            user_update.email,
            password_hash
        )
        .fetch_optional(pool)
        .await?;

        Ok(updated_user)
    }

    // Delete user
    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!("DELETE FROM users WHERE id = $1", id.to_string())
            .execute(pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    // Check if username exists
    pub async fn exists_by_username(pool: &PgPool, username: &str) -> Result<bool, sqlx::Error> {
        let count = sqlx::query_scalar!("SELECT COUNT(*) FROM users WHERE username = $1", username)
            .fetch_one(pool)
            .await?;

        Ok(count.unwrap_or(0) > 0)
    }

    // Check if email exists
    pub async fn exists_by_email(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
        let count = sqlx::query_scalar!("SELECT COUNT(*) FROM users WHERE email = $1", email)
            .fetch_one(pool)
            .await?;

        Ok(count.unwrap_or(0) > 0)
    }

    // Check if username exists excluding specific user ID (for updates)
    pub async fn exists_by_username_excluding_id(
        pool: &PgPool,
        username: &str,
        exclude_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM users WHERE username = $1 AND id != $2",
            username,
            exclude_id.to_string()
        )
        .fetch_one(pool)
        .await?;

        Ok(count.unwrap_or(0) > 0)
    }

    // Check if email exists excluding specific user ID (for updates)
    pub async fn exists_by_email_excluding_id(
        pool: &PgPool,
        email: &str,
        exclude_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM users WHERE email = $1 AND id != $2",
            email,
            exclude_id.to_string()
        )
        .fetch_one(pool)
        .await?;

        Ok(count.unwrap_or(0) > 0)
    }
}
