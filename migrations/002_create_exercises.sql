CREATE TABLE exercises (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    muscle_groups JSONB NOT NULL DEFAULT '[]',
    equipment_needed TEXT,
    exercise_type TEXT NOT NULL CHECK (exercise_type IN ('strength', 'cardio', 'flexibility', 'balance', 'sports')),
    instructions TEXT,
    created_at TEXT NOT NULL
);

-- Create indexes for better query performance
CREATE INDEX idx_exercises_name ON exercises(name);
CREATE INDEX idx_exercises_type ON exercises(exercise_type);
CREATE INDEX idx_exercises_muscle_groups ON exercises USING GIN (muscle_groups);

-- Insert some common exercises to get started
INSERT INTO exercises (id, name, description, muscle_groups, equipment_needed, exercise_type, instructions, created_at) VALUES
(
    gen_random_uuid()::text,
    'Push-ups',
    'A classic upper body exercise',
    '["chest", "shoulders", "triceps", "core"]',
    'none',
    'strength',
    'Start in plank position, lower body until chest nearly touches ground, push back up',
    NOW()::text
),
(
    gen_random_uuid()::text,
    'Squats',
    'Lower body compound movement',
    '["quadriceps", "glutes", "hamstrings", "calves"]',
    'none',
    'strength',
    'Stand with feet shoulder-width apart, lower hips back and down, return to standing',
    NOW()::text
),
(
    gen_random_uuid()::text,
    'Pull-ups',
    'Upper body pulling exercise',
    '["lats", "biceps", "rhomboids", "rear_delts"]',
    'pull-up bar',
    'strength',
    'Hang from bar with overhand grip, pull body up until chin clears bar, lower with control',
    NOW()::text
),
(
    gen_random_uuid()::text,
    'Running',
    'Cardiovascular endurance exercise',
    '["legs", "glutes", "core", "cardiovascular"]',
    'none',
    'cardio',
    'Maintain steady pace, focus on breathing and form',
    NOW()::text
),
(
    gen_random_uuid()::text,
    'Plank',
    'Core stability exercise',
    '["core", "shoulders", "glutes"]',
    'none',
    'strength',
    'Hold straight line from head to heels, engage core muscles',
    NOW()::text
);
