# Repository Tests

This directory contains comprehensive integration tests for the repository layer of the Axum Workout API.

## Overview

The tests follow the AI development rules for this project, which specify:
- **Repository Layer**: Integration tests for database operations
- **Service Layer**: Unit tests for business logic (when implemented)
- **Handler Layer**: Unit tests for HTTP concerns (when implemented)

## Test Structure

### Test Files

- `user_repository_tests.rs` - Tests for `UserRepository`
- `exercise_repository_tests.rs` - Tests for `ExerciseRepository` 
- `workout_repository_tests.rs` - Tests for `WorkoutRepository`
- `common/mod.rs` - Shared test utilities and helpers

### Test Database Setup

Each test creates and tears down its own isolated PostgreSQL database to ensure:
- Test isolation
- No data pollution between tests
- Ability to run tests in parallel
- Consistent test results

## Running Tests

### Prerequisites

1. **PostgreSQL Server**: Ensure PostgreSQL is running locally
2. **Database URL**: Set the `DATABASE_URL` environment variable or use the default:
   ```bash
   export DATABASE_URL="postgres://postgres:password@localhost"
   ```

### Running All Repository Tests

```bash
# Run all tests (may run in parallel)
cargo test

# Run with single thread for stability
cargo test -- --test-threads=1
```

### Running Specific Repository Tests

```bash
# User repository tests
cargo test --test user_repository_tests -- --test-threads=1

# Exercise repository tests  
cargo test --test exercise_repository_tests -- --test-threads=1

# Workout repository tests
cargo test --test workout_repository_tests -- --test-threads=1
```

### Running Individual Test Functions

```bash
# Run a specific test
cargo test --test user_repository_tests test_insert_user_success -- --test-threads=1

# Run tests matching a pattern
cargo test --test user_repository_tests insert -- --test-threads=1
```

## Test Coverage

### UserRepository Tests (19 tests)

**CRUD Operations:**
- ✅ `test_insert_user_success` - Basic user creation
- ✅ `test_insert_user_duplicate_username` - Unique constraint validation
- ✅ `test_insert_user_duplicate_email` - Unique constraint validation
- ✅ `test_find_by_id_success` - Find user by UUID
- ✅ `test_find_by_id_not_found` - Handle non-existent user
- ✅ `test_find_by_username_success` - Find by username
- ✅ `test_find_by_username_not_found` - Handle non-existent username
- ✅ `test_find_by_email_success` - Find by email
- ✅ `test_find_by_email_not_found` - Handle non-existent email
- ✅ `test_find_all_users` - List all users
- ✅ `test_update_user_success` - Full user update
- ✅ `test_update_user_with_password` - Password update
- ✅ `test_update_user_not_found` - Update non-existent user
- ✅ `test_delete_user_success` - User deletion
- ✅ `test_delete_user_not_found` - Delete non-existent user

**Utility Functions:**
- ✅ `test_exists_by_username` - Username existence check
- ✅ `test_exists_by_email` - Email existence check
- ✅ `test_exists_by_username_excluding_id` - Update validation
- ✅ `test_exists_by_email_excluding_id` - Update validation

### ExerciseRepository Tests (17 tests)

**CRUD Operations:**
- ✅ `test_insert_exercise_success` - Basic exercise creation
- ✅ `test_insert_exercise_duplicate_name` - Name uniqueness
- ✅ `test_find_by_id_success` - Find by UUID
- ✅ `test_find_by_id_not_found` - Handle non-existent exercise
- ✅ `test_find_by_name_success` - Find by name
- ✅ `test_find_by_name_not_found` - Handle non-existent name
- ✅ `test_find_all_exercises` - List all exercises
- ✅ `test_update_exercise_success` - Full exercise update
- ✅ `test_update_exercise_partial` - Partial update
- ✅ `test_update_exercise_not_found` - Update non-existent exercise
- ✅ `test_delete_exercise_success` - Exercise deletion
- ✅ `test_delete_exercise_not_found` - Delete non-existent exercise

**Search & Filter Operations:**
- ✅ `test_find_by_type` - Filter by exercise type
- ✅ `test_find_by_muscle_group` - Filter by muscle groups (JSONB)
- ✅ `test_search_by_name_pattern` - Pattern matching search

**Validation & Constraints:**
- ✅ `test_exists_by_name` - Name existence check
- ✅ `test_exercise_type_validation` - Database constraint validation

### WorkoutRepository Tests (19 tests)

**CRUD Operations:**
- ✅ `test_insert_workout_success` - Basic workout creation
- ✅ `test_find_by_id_success` - Find by UUID
- ✅ `test_find_by_id_not_found` - Handle non-existent workout
- ✅ `test_update_workout_success` - Full workout update
- ✅ `test_update_workout_partial` - Partial update
- ✅ `test_delete_workout_success` - Workout deletion

**Authorization & Security:**
- ✅ `test_find_by_id_and_user_success` - User-specific lookup
- ✅ `test_find_by_id_and_user_wrong_user` - Authorization check
- ✅ `test_update_workout_wrong_user` - Update authorization
- ✅ `test_delete_workout_wrong_user` - Delete authorization

**User-Specific Operations:**
- ✅ `test_find_by_user_id` - List user's workouts
- ✅ `test_find_by_user_and_date_range` - Date range filtering
- ✅ `test_find_recent_by_user` - Recent workouts with limit
- ✅ `test_search_by_name_pattern` - Pattern matching search

**Analytics & Statistics:**
- ✅ `test_count_by_user` - Count user's workouts
- ✅ `test_total_duration_by_user` - Sum workout durations

**Validation & Constraints:**
- ✅ `test_exists_by_name_and_user` - Name uniqueness per user
- ✅ `test_exists_by_name_and_user_excluding_id` - Update validation

**Database Relationships:**
- ✅ `test_workout_cascading_delete` - Foreign key cascade

## Test Utilities

### TestDb Helper

The `TestDb` struct provides automatic database setup and cleanup:

```rust
let test_db = TestDb::new().await;
// Use test_db.pool for database operations
test_db.cleanup().await; // Automatic cleanup
```

### Test Data Helpers

Located in `common/test_data` module:

```rust
// Create test users
let user = test_data::create_test_user();
let user = test_data::create_test_user_with_data("username", "email@test.com");

// Create test exercises
let exercise = test_data::create_test_exercise();
let exercise = test_data::create_test_exercise_with_name("Exercise Name");

// Create test workouts
let workout = test_data::create_test_workout(user_id);
let workout = test_data::create_test_workout_with_name("Workout Name");
```

## Key Testing Principles

### 1. Database Isolation
- Each test uses a unique database
- No shared state between tests
- Automatic cleanup prevents pollution

### 2. Error Case Coverage
- Test both success and failure scenarios
- Validate constraint violations
- Test authorization boundaries

### 3. Data Integrity
- Test foreign key relationships
- Validate cascading operations
- Test unique constraints

### 4. Real Database Testing
- Tests run against actual PostgreSQL
- Migration scripts are executed
- Database constraints are enforced

## Adding New Tests

### For New Repository Methods

1. Add test function following naming convention: `test_method_name_scenario`
2. Use `TestDb::new().await` for database setup
3. Call `test_db.cleanup().await` at the end
4. Test both success and error cases

### Example Test Structure

```rust
#[tokio::test]
async fn test_new_method_success() {
    let test_db = TestDb::new().await;
    let pool = &test_db.pool;

    // Arrange - set up test data
    let test_data = create_test_data();
    
    // Act - call the method being tested
    let result = Repository::new_method(pool, test_data).await;
    
    // Assert - verify the results
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value.field, expected_value);
    
    test_db.cleanup().await;
}
```

## Troubleshooting

### Database Connection Issues
- Ensure PostgreSQL is running
- Check `DATABASE_URL` environment variable
- Verify database user has creation privileges

### Test Failures
- Run tests with `--test-threads=1` to avoid race conditions
- Check if PostgreSQL extensions are installed
- Ensure migration files are up to date

### Performance Issues
- Tests create/drop databases - expect some overhead
- Use `--test-threads=1` for consistency over speed
- Consider test database optimization for large test suites

## Future Test Additions

When new layers are implemented:

1. **Service Layer Tests** - Unit tests for business logic
2. **Handler Layer Tests** - Unit tests for HTTP concerns  
3. **Integration Tests** - End-to-end API testing
4. **Performance Tests** - Repository operation benchmarks