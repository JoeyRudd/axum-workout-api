pub mod errors;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod repositories;
pub mod routes;
pub mod services;

// Re-export commonly used items for convenience
pub use errors::AppError;
pub use middleware::{admin_middleware, auth_middleware, extract_claims};
pub use models::{auth, exercise, user, workout};
pub use repositories::{ExerciseRepository, UserRepository, WorkoutRepository};
pub use routes::create_router;
pub use services::{AuthService, JwtService, UserService};
