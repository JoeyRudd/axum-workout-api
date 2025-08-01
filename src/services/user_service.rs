use crate::errors::AppError;
use crate::models::user::{User, UserCreate, UserUpdate};
use crate::repositories::UserRepository;
use bcrypt::{DEFAULT_COST, hash, verify};
use sqlx::PgPool;
use uuid::Uuid;

pub struct UserService;

impl UserService {
    /// Register a new user with password hashing
    pub async fn register(pool: &PgPool, user_create: UserCreate) -> Result<User, AppError> {
        // Validate input
        Self::validate_user_create(&user_create)?;

        // Check if username already exists
        if UserRepository::exists_by_username(pool, &user_create.username).await? {
            return Err(AppError::BadRequest(format!(
                "Username '{}' is already taken",
                user_create.username
            )));
        }

        // Check if email already exists
        if UserRepository::exists_by_email(pool, &user_create.email).await? {
            return Err(AppError::BadRequest(format!(
                "Email '{}' is already registered",
                user_create.email
            )));
        }

        // Hash the password
        let password_hash = Self::hash_password(&user_create.password)?;

        // Insert user into database
        UserRepository::insert(pool, user_create, password_hash)
            .await
            .map_err(|e| AppError::Database(e))
    }

    /// Authenticate user with username/email and password
    pub async fn authenticate(
        pool: &PgPool,
        identifier: &str, // Can be username or email
        password: &str,
    ) -> Result<User, AppError> {
        // Try to find user by username first, then by email
        let user = if identifier.contains('@') {
            UserRepository::find_by_email(pool, identifier).await?
        } else {
            UserRepository::find_by_username(pool, identifier).await?
        };

        let user = user.ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;

        // Verify password
        if !Self::verify_password(password, &user.password_hash)? {
            return Err(AppError::Unauthorized("Invalid credentials".to_string()));
        }

        Ok(user)
    }

    /// Get user by ID
    pub async fn get_user_by_id(pool: &PgPool, user_id: Uuid) -> Result<User, AppError> {
        UserRepository::find_by_id(pool, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("User with ID {} not found", user_id)))
    }

    /// Get user by username
    pub async fn get_user_by_username(pool: &PgPool, username: &str) -> Result<User, AppError> {
        UserRepository::find_by_username(pool, username)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("User '{}' not found", username)))
    }

    /// Get user by email
    pub async fn get_user_by_email(pool: &PgPool, email: &str) -> Result<User, AppError> {
        UserRepository::find_by_email(pool, email)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("User with email '{}' not found", email)))
    }

    /// Get all users (admin functionality)
    pub async fn get_all_users(pool: &PgPool) -> Result<Vec<User>, AppError> {
        UserRepository::find_all(pool)
            .await
            .map_err(|e| AppError::Database(e))
    }

    /// Update user profile
    pub async fn update_user(
        pool: &PgPool,
        user_id: Uuid,
        user_update: UserUpdate,
    ) -> Result<User, AppError> {
        // Validate the update data
        Self::validate_user_update(&user_update)?;

        // Check if username is being changed and if it's available
        if let Some(ref new_username) = user_update.username {
            if UserRepository::exists_by_username_excluding_id(pool, new_username, user_id).await? {
                return Err(AppError::BadRequest(format!(
                    "Username '{}' is already taken",
                    new_username
                )));
            }
        }

        // Check if email is being changed and if it's available
        if let Some(ref new_email) = user_update.email {
            if UserRepository::exists_by_email_excluding_id(pool, new_email, user_id).await? {
                return Err(AppError::BadRequest(format!(
                    "Email '{}' is already registered",
                    new_email
                )));
            }
        }

        // Hash new password if provided
        let password_hash = if user_update.password.is_some() {
            Some(Self::hash_password(user_update.password.as_ref().unwrap())?)
        } else {
            None
        };

        // Update user in database
        UserRepository::update(pool, user_id, user_update, password_hash)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("User with ID {} not found", user_id)))
    }

    /// Delete user account
    pub async fn delete_user(pool: &PgPool, user_id: Uuid) -> Result<(), AppError> {
        let deleted = UserRepository::delete(pool, user_id).await?;

        if !deleted {
            return Err(AppError::NotFound(format!(
                "User with ID {} not found",
                user_id
            )));
        }

        Ok(())
    }

    /// Change user password
    pub async fn change_password(
        pool: &PgPool,
        user_id: Uuid,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AppError> {
        // Get the user to verify current password
        let user = Self::get_user_by_id(pool, user_id).await?;

        // Verify current password
        if !Self::verify_password(current_password, &user.password_hash)? {
            return Err(AppError::Unauthorized(
                "Current password is incorrect".to_string(),
            ));
        }

        // Validate new password
        Self::validate_password(new_password)?;

        // Hash new password
        let new_password_hash = Self::hash_password(new_password)?;

        // Update password in database
        let user_update = UserUpdate {
            username: None,
            email: None,
            password: Some(new_password.to_string()),
        };

        UserRepository::update(pool, user_id, user_update, Some(new_password_hash))
            .await?
            .ok_or_else(|| AppError::NotFound(format!("User with ID {} not found", user_id)))?;

        Ok(())
    }

    /// Check if user exists by username
    pub async fn user_exists_by_username(pool: &PgPool, username: &str) -> Result<bool, AppError> {
        UserRepository::exists_by_username(pool, username)
            .await
            .map_err(|e| AppError::Database(e))
    }

    /// Check if user exists by email
    pub async fn user_exists_by_email(pool: &PgPool, email: &str) -> Result<bool, AppError> {
        UserRepository::exists_by_email(pool, email)
            .await
            .map_err(|e| AppError::Database(e))
    }

    // Private helper methods

    /// Hash a password using bcrypt
    fn hash_password(password: &str) -> Result<String, AppError> {
        hash(password, DEFAULT_COST)
            .map_err(|e| AppError::InternalServerError(format!("Failed to hash password: {}", e)))
    }

    /// Verify a password against a hash
    fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
        verify(password, hash)
            .map_err(|e| AppError::InternalServerError(format!("Failed to verify password: {}", e)))
    }

    /// Validate user creation data
    fn validate_user_create(user_create: &UserCreate) -> Result<(), AppError> {
        // Validate username
        Self::validate_username(&user_create.username)?;

        // Validate email
        Self::validate_email(&user_create.email)?;

        // Validate password
        Self::validate_password(&user_create.password)?;

        Ok(())
    }

    /// Validate user update data
    fn validate_user_update(user_update: &UserUpdate) -> Result<(), AppError> {
        // Validate username if provided
        if let Some(ref username) = user_update.username {
            Self::validate_username(username)?;
        }

        // Validate email if provided
        if let Some(ref email) = user_update.email {
            Self::validate_email(email)?;
        }

        // Validate password if provided
        if let Some(ref password) = user_update.password {
            Self::validate_password(password)?;
        }

        Ok(())
    }

    /// Validate username format and requirements
    fn validate_username(username: &str) -> Result<(), AppError> {
        if username.is_empty() {
            return Err(AppError::BadRequest("Username cannot be empty".to_string()));
        }

        if username.len() < 3 {
            return Err(AppError::BadRequest(
                "Username must be at least 3 characters long".to_string(),
            ));
        }

        if username.len() > 50 {
            return Err(AppError::BadRequest(
                "Username cannot be longer than 50 characters".to_string(),
            ));
        }

        // Check for valid characters (alphanumeric, underscore, hyphen)
        if !username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(AppError::BadRequest(
                "Username can only contain letters, numbers, underscores, and hyphens".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate email format
    fn validate_email(email: &str) -> Result<(), AppError> {
        if email.is_empty() {
            return Err(AppError::BadRequest("Email cannot be empty".to_string()));
        }

        if email.len() > 254 {
            return Err(AppError::BadRequest(
                "Email cannot be longer than 254 characters".to_string(),
            ));
        }

        // Basic email validation (contains @ and .)
        if !email.contains('@') || !email.contains('.') {
            return Err(AppError::BadRequest("Invalid email format".to_string()));
        }

        // More thorough email validation
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(AppError::BadRequest("Invalid email format".to_string()));
        }

        // Check domain part has at least one dot and valid characters
        let domain = parts[1];
        if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
            return Err(AppError::BadRequest("Invalid email domain".to_string()));
        }

        Ok(())
    }

    /// Validate password strength
    fn validate_password(password: &str) -> Result<(), AppError> {
        if password.is_empty() {
            return Err(AppError::BadRequest("Password cannot be empty".to_string()));
        }

        if password.len() < 8 {
            return Err(AppError::BadRequest(
                "Password must be at least 8 characters long".to_string(),
            ));
        }

        if password.len() > 128 {
            return Err(AppError::BadRequest(
                "Password cannot be longer than 128 characters".to_string(),
            ));
        }

        // Check for at least one uppercase letter
        if !password.chars().any(|c| c.is_uppercase()) {
            return Err(AppError::BadRequest(
                "Password must contain at least one uppercase letter".to_string(),
            ));
        }

        // Check for at least one lowercase letter
        if !password.chars().any(|c| c.is_lowercase()) {
            return Err(AppError::BadRequest(
                "Password must contain at least one lowercase letter".to_string(),
            ));
        }

        // Check for at least one digit
        if !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(AppError::BadRequest(
                "Password must contain at least one number".to_string(),
            ));
        }

        Ok(())
    }
}
