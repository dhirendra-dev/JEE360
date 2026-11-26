ALTER TABLE users ADD COLUMN password_hash_scheme TEXT NOT NULL DEFAULT 'pbkdf2-server';
