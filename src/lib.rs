pub mod errors;
pub mod models;
pub mod repositories;
pub mod services;

// Re-export commonly used items for convenience
pub use errors::AppError;
pub use models::{exercise, user, workout};
pub use repositories::{ExerciseRepository, UserRepository, WorkoutRepository};
pub use services::UserService;
