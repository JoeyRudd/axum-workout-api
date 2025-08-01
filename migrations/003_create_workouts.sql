CREATE TABLE workouts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    workout_date TEXT NOT NULL,
    duration_minutes INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT
);

-- Create indexes for better query performance
CREATE INDEX idx_workouts_user_id ON workouts(user_id);
CREATE INDEX idx_workouts_workout_date ON workouts(workout_date);
CREATE INDEX idx_workouts_user_workout_date ON workouts(user_id, workout_date);

-- Create a compound index for user-specific queries ordered by date
CREATE INDEX idx_workouts_user_date_desc ON workouts(user_id, workout_date DESC);

-- Sample data can be added later via service layer
