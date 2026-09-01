const Database = require('better-sqlite3');
const path = require('path');

const caminhoBanco = path.join(__dirname, 'database.sqlite');

const db = new Database(caminhoBanco);

// Ativa integridade de relacionamentos.
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

// ==========================================
// TABELA DE USUÁRIOS
// ==========================================

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        telefone TEXT,
        email TEXT NOT NULL UNIQUE,
        nivel TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

// ==========================================
// TABELA DE SESSÕES
// ==========================================

db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    )
`);

// ==========================================
// TABELA DE POSTS
// ==========================================

db.exec(`
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    )
`);

// ==========================================
// TABELA DE COMENTÁRIOS
// ==========================================

db.exec(`
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (post_id)
            REFERENCES posts(id)
            ON DELETE CASCADE,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    )
`);

// ==========================================
// TABELA DO DIÁRIO DE TRADES
// ==========================================

db.exec(`
    CREATE TABLE IF NOT EXISTS trades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        asset TEXT NOT NULL,
        order_type TEXT NOT NULL,
        entry_price REAL NOT NULL,
        exit_price REAL NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE,

        CHECK (order_type IN ('compra', 'venda')),
        CHECK (entry_price > 0),
        CHECK (exit_price > 0)
    )
`);


// ==========================================
// ÍNDICES
// ==========================================

db.exec(`
    CREATE INDEX IF NOT EXISTS idx_sessions_user
    ON sessions(user_id);

    CREATE INDEX IF NOT EXISTS idx_sessions_expiration
    ON sessions(expires_at);

    CREATE INDEX IF NOT EXISTS idx_posts_user
    ON posts(user_id);

    CREATE INDEX IF NOT EXISTS idx_comments_post
    ON comments(post_id);

    CREATE INDEX IF NOT EXISTS idx_comments_user
    ON comments(user_id);

    CREATE INDEX IF NOT EXISTS idx_trades_user
    ON trades(user_id);

    CREATE INDEX IF NOT EXISTS idx_trades_user_created
    ON trades(user_id, created_at DESC);
`);

module.exports = db;