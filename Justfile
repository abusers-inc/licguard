create-entities:
    cargo test -p migration && sea generate entity --database-url "sqlite://server/migration/db.data" -o server/src/entities    
