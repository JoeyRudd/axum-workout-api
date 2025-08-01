use axum_workout_api::{create_router, models::auth::JwtConfig, services::AuthService};
use sqlx::postgres::PgPool;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get database URL from environment or use default
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/workout_db".to_string());

    println!("Connecting to database: {}", database_url);

    // Connect to database
    let pool = PgPool::connect(&database_url).await?;

    // Run migrations
    println!("Running database migrations...");
    sqlx::migrate!("./migrations").run(&pool).await?;
    println!("Database migrations completed successfully");

    // Initialize JWT configuration
    let jwt_config = JwtConfig::default();

    // Initialize authentication service
    let auth_service = Arc::new(AuthService::new(jwt_config));

    // Create router with all routes and middleware
    let app = create_router(pool, auth_service);

    // Get port from environment or use default
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .unwrap_or(3000);

    let addr = format!("0.0.0.0:{}", port);

    println!("Server starting on http://{}", addr);
    println!("Available endpoints:");
    println!("  Health Check: GET http://{}/health", addr);
    println!("  Register: POST http://{}/api/auth/register", addr);
    println!("  Login: POST http://{}/api/auth/login", addr);
    println!("  Refresh Token: POST http://{}/api/auth/refresh", addr);
    println!(
        "  Check Username: GET http://{}/api/auth/check-username?username=test",
        addr
    );
    println!(
        "  Check Email: GET http://{}/api/auth/check-email?email=test@example.com",
        addr
    );

    // Start server
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("Server ready and listening on http://{}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}
