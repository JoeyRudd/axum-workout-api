//! Complete Authentication System Demo
//!
//! This example demonstrates how to use the JWT-based authentication system
//! with Axum HTTP handlers, middleware, and protected routes.
//!
//! To run this example:
//! 1. Set DATABASE_URL environment variable
//! 2. Run: cargo run --example auth_demo
//! 3. Test the endpoints with curl or a REST client

use axum::{
    Router,
    extract::{Path, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::{get, post},
};
use axum_workout_api::{
    errors::AppError,
    middleware::auth::extract_claims,
    models::auth::{Claims, JwtConfig, LoginRequest, LoginResponse, RegisterRequest, UserResponse},
    services::{AuthService, UserService},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

/// Application state
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub auth_service: Arc<AuthService>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::init();

    // Get database URL from environment
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/workout_db".to_string());

    println!("🔗 Connecting to database: {}", database_url);

    // Connect to database
    let pool = PgPool::connect(&database_url).await?;

    // Run migrations
    println!("🔄 Running database migrations...");
    sqlx::migrate!("./migrations").run(&pool).await?;

    // Initialize JWT configuration
    let jwt_config = JwtConfig {
        secret: std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "your-super-secret-jwt-key-change-in-production".to_string()),
        access_token_expiry: 15 * 60,        // 15 minutes
        refresh_token_expiry: 7 * 24 * 3600, // 7 days
        issuer: "axum-workout-api".to_string(),
    };

    // Create authentication service
    let auth_service = Arc::new(AuthService::new(jwt_config));

    // Create application state
    let state = AppState { pool, auth_service };

    // Create router
    let app = create_router(state);

    // Start server
    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    println!("🚀 Server running on http://0.0.0.0:3000");

    // Print API documentation
    print_api_documentation();

    // Start the server
    axum::serve(listener, app).await?;

    Ok(())
}

/// Create the application router
fn create_router(state: AppState) -> Router {
    Router::new()
        // Public routes
        .route("/health", get(health_check))
        .route("/api/auth/register", post(register))
        .route("/api/auth/login", post(login))
        .route("/api/users/check/:username", get(check_username))
        // Protected routes (require authentication)
        .route("/api/auth/me", get(me))
        .route("/api/users/:user_id", get(get_user))
        .route("/api/admin/users", get(admin_get_users))
        // Apply auth middleware to protected routes
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        // Add CORS
        .layer(CorsLayer::permissive())
        // Add state
        .with_state(state)
}

// ===== MIDDLEWARE =====

/// Authentication middleware
async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, AppError> {
    let path = request.uri().path();

    // Skip auth for public routes
    if is_public_route(path) {
        return Ok(next.run(request).await);
    }

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing authorization header".to_string()))?;

    // Extract token
    let token = state.auth_service.extract_token_from_header(auth_header)?;

    // Validate token
    let claims = state.auth_service.validate_token(token)?;

    // Verify user still exists
    state
        .auth_service
        .get_current_user(&state.pool, &claims)
        .await?;

    // Add claims to request
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

fn is_public_route(path: &str) -> bool {
    matches!(
        path,
        "/health" | "/api/auth/register" | "/api/auth/login" | "/api/users/check"
    ) || path.starts_with("/api/users/check/")
}

// ===== HANDLERS =====

/// Health check
async fn health_check() -> &'static str {
    "🟢 API is healthy!"
}

/// Register a new user
async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    println!("📝 Registering user: {}", request.username);
    let response = state.auth_service.register(&state.pool, request).await?;
    println!("✅ User registered successfully");
    Ok(Json(response))
}

/// Login user
async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    println!("🔐 Login attempt for: {}", request.identifier);
    let response = state.auth_service.login(&state.pool, request).await?;
    println!("✅ User logged in successfully");
    Ok(Json(response))
}

/// Get current user (protected route)
async fn me(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<UserResponse>, AppError> {
    let claims = extract_claims(&request)?;
    println!("👤 Getting current user: {}", claims.username);
    let user = state
        .auth_service
        .get_current_user(&state.pool, &claims)
        .await?;
    Ok(Json(user))
}

/// Get user by ID (protected route with authorization)
async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    request: Request,
) -> Result<Json<UserResponse>, AppError> {
    let claims = extract_claims(&request)?;
    let target_user_id = uuid::Uuid::parse_str(&user_id)
        .map_err(|_| AppError::BadRequest("Invalid user ID".to_string()))?;

    println!(
        "🔍 User {} requesting user {}",
        claims.username, target_user_id
    );

    // Check if user can access this resource
    if !state
        .auth_service
        .can_access_resource(&claims, target_user_id)
    {
        return Err(AppError::Unauthorized(
            "You can only access your own profile".to_string(),
        ));
    }

    let user = UserService::get_user_by_id(&state.pool, target_user_id).await?;
    Ok(Json(UserResponse::from(user)))
}

/// Admin endpoint - get all users (requires admin role)
async fn admin_get_users(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<AdminUsersResponse>, AppError> {
    let claims = extract_claims(&request)?;

    println!("👑 Admin request from: {}", claims.username);

    // Check admin role
    if !state.auth_service.is_admin(&claims) {
        return Err(AppError::Unauthorized("Admin access required".to_string()));
    }

    let users = state
        .auth_service
        .get_all_users(&state.pool, &claims)
        .await?;

    Ok(Json(AdminUsersResponse {
        users,
        total: users.len(),
        requested_by: claims.username,
    }))
}

/// Check username availability (public route)
async fn check_username(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<UsernameCheckResponse>, AppError> {
    println!("🔍 Checking username availability: {}", username);
    let is_available = state
        .auth_service
        .check_username_availability(&state.pool, &username)
        .await?;

    Ok(Json(UsernameCheckResponse {
        username,
        available: is_available,
        message: if is_available {
            "Username is available".to_string()
        } else {
            "Username is already taken".to_string()
        },
    }))
}

// ===== RESPONSE TYPES =====

#[derive(Serialize)]
struct AdminUsersResponse {
    users: Vec<UserResponse>,
    total: usize,
    requested_by: String,
}

#[derive(Serialize)]
struct UsernameCheckResponse {
    username: String,
    available: bool,
    message: String,
}

// ===== DOCUMENTATION =====

fn print_api_documentation() {
    println!("\n📚 Authentication API Demo");
    println!("==========================");

    println!("\n🌐 Available Endpoints:");
    println!("  GET  /health                          - Health check (public)");
    println!("  POST /api/auth/register               - Register new user (public)");
    println!("  POST /api/auth/login                  - Login user (public)");
    println!("  GET  /api/users/check/:username       - Check username availability (public)");
    println!("  GET  /api/auth/me                     - Get current user (protected)");
    println!("  GET  /api/users/:user_id              - Get user by ID (protected + ownership)");
    println!("  GET  /api/admin/users                 - Get all users (admin only)");

    println!("\n🔐 Authentication Flow:");
    println!("1. Register: POST /api/auth/register");
    println!("2. Login: POST /api/auth/login (get access_token)");
    println!("3. Use token: Add 'Authorization: Bearer <token>' header");
    println!("4. Access protected routes with valid token");

    println!("\n📋 Example Usage:");
    println!("=================");

    println!("\n1️⃣  Health Check:");
    println!("curl http://localhost:3000/health");

    println!("\n2️⃣  Register:");
    println!("curl -X POST http://localhost:3000/api/auth/register \\");
    println!("  -H 'Content-Type: application/json' \\");
    println!("  -d '{{");
    println!("    \"username\": \"john_doe\",");
    println!("    \"email\": \"john@example.com\",");
    println!("    \"password\": \"SecurePass123\"");
    println!("  }}'");

    println!("\n3️⃣  Login:");
    println!("curl -X POST http://localhost:3000/api/auth/login \\");
    println!("  -H 'Content-Type: application/json' \\");
    println!("  -d '{{");
    println!("    \"identifier\": \"john_doe\",");
    println!("    \"password\": \"SecurePass123\"");
    println!("  }}'");

    println!("\n4️⃣  Check Username Availability:");
    println!("curl http://localhost:3000/api/users/check/testuser");

    println!("\n5️⃣  Get Current User (Protected):");
    println!("curl -H 'Authorization: Bearer <YOUR_TOKEN>' \\");
    println!("  http://localhost:3000/api/auth/me");

    println!("\n6️⃣  Access Admin Endpoint (Admin only):");
    println!("curl -H 'Authorization: Bearer <ADMIN_TOKEN>' \\");
    println!("  http://localhost:3000/api/admin/users");

    println!("\n🛡️  Security Features Demonstrated:");
    println!("✅ JWT token-based authentication");
    println!("✅ Password hashing with bcrypt");
    println!("✅ Role-based access control (admin vs user)");
    println!("✅ Resource ownership validation");
    println!("✅ Automatic token validation middleware");
    println!("✅ Proper error handling and responses");

    println!("\n🎯 Try the API:");
    println!("===============");
    println!("Start with registering a user, then login to get a token,");
    println!("and use that token to access protected endpoints!");
    println!("");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_public_route() {
        assert!(is_public_route("/health"));
        assert!(is_public_route("/api/auth/register"));
        assert!(is_public_route("/api/auth/login"));
        assert!(is_public_route("/api/users/check/testuser"));
        assert!(!is_public_route("/api/auth/me"));
        assert!(!is_public_route("/api/admin/users"));
    }

    #[test]
    fn test_response_serialization() {
        let response = UsernameCheckResponse {
            username: "test".to_string(),
            available: true,
            message: "Available".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"available\":true"));
    }
}
