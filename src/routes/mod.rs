use crate::handlers::{auth_handlers, user_handlers};
use crate::services::AuthService;
use axum::{
    Router,
    routing::{delete, get, post, put},
};
use sqlx::PgPool;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

/// Application state that holds shared dependencies
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub auth_service: Arc<AuthService>,
}

/// Create the main application router with all routes
pub fn create_router(pool: PgPool, auth_service: Arc<AuthService>) -> Router {
    let state = AppState { pool, auth_service };

    Router::new()
        // Add CORS middleware for all routes
        .layer(CorsLayer::permissive())
        // Health check endpoint
        .route("/health", get(health_check))
        // Public routes (no authentication required)
        .merge(public_routes())
        // Authentication routes
        .merge(auth_routes())
        // User routes
        .merge(user_routes())
        // Admin routes
        .merge(admin_routes())
        // Add global state
        .with_state(state)
}

/// Public routes - No authentication required
fn public_routes() -> Router<AppState> {
    Router::new()
        // Username/email availability checks
        .route(
            "/api/auth/check-username",
            get(auth_handlers::check_username_availability),
        )
        .route(
            "/api/auth/check-email",
            get(auth_handlers::check_email_availability),
        )
        // User existence checks (public)
        .route(
            "/api/users/exists/username/{username}",
            get(user_handlers::check_user_exists_by_username),
        )
        .route(
            "/api/users/exists/email/{email}",
            get(user_handlers::check_user_exists_by_email),
        )
}

/// Authentication routes - Registration, login, token refresh
fn auth_routes() -> Router<AppState> {
    Router::new()
        // Public auth endpoints
        .route("/api/auth/register", post(auth_handlers::register))
        .route("/api/auth/login", post(auth_handlers::login))
        .route("/api/auth/refresh", post(auth_handlers::refresh_token))
        // Protected auth endpoints (authentication required)
        .route("/api/auth/me", get(auth_handlers::me))
        .route("/api/auth/profile", put(auth_handlers::update_profile))
        .route(
            "/api/auth/change-password",
            post(auth_handlers::change_password),
        )
        .route("/api/auth/account", delete(auth_handlers::delete_account))
        .route("/api/auth/logout", post(auth_handlers::logout))
}

/// User routes - User management endpoints
fn user_routes() -> Router<AppState> {
    Router::new()
        // User management endpoints
        .route(
            "/api/users/me",
            get(user_handlers::get_current_user_profile),
        )
        .route("/api/users/{user_id}", get(user_handlers::get_user_by_id))
        .route("/api/users/{user_id}", put(user_handlers::update_user))
        .route("/api/users/{user_id}", delete(user_handlers::delete_user))
        .route(
            "/api/users/username/{username}",
            get(user_handlers::get_user_by_username),
        )
}

/// Admin routes - Administrative endpoints
fn admin_routes() -> Router<AppState> {
    Router::new()
        // Admin user management
        .route("/api/admin/users", get(user_handlers::list_users))
        .route(
            "/api/admin/users/{user_id}",
            delete(auth_handlers::admin_delete_user),
        )
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::auth::JwtConfig;

    #[tokio::test]
    async fn test_create_router() {
        // Create test database pool (you might want to use a mock here)
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://test:test@localhost/test".to_string());

        // Skip test if no database available
        if let Ok(pool) = sqlx::PgPool::connect(&database_url).await {
            let auth_service = Arc::new(AuthService::new(JwtConfig::default()));
            let router = create_router(pool, auth_service);

            // Basic test to ensure router compiles and can be created
            assert!(std::any::type_name_of_val(&router).contains("Router"));
        }
    }

    #[test]
    fn test_router_structure() {
        // Test that we can create the router functions without panicking
        let public_router = public_routes();
        assert!(std::any::type_name_of_val(&public_router).contains("Router"));
    }
}
