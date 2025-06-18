const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database('db.sqlite');
const SECRET = process.env.JWT_SECRET || 'dev_secret';

require('dotenv').config();

app.use(cors());
app.use(express.json());

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT
    );

    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        disabled BOOLEAN DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    `)

function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });

    try {
        const payload = jwt.verify(token, SECRET);
        req.user = payload;
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;
    const hash = await bcrypt.hash(password, 10);
    try {
        const stmt = db.prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        const result = stmt.run(username, email, hash);
        res.json({ id: result.lastInsertRowid });
    } catch (error) {
        res.status(400).json({ error: "User already exists" });
    }
})

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const stmt = db.prepare("SELECT * FROM users WHERE username = ?");
    const user = stmt.get(username);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    bcrypt.compare(password, user.password, (err, match) => {
        if (err || !match) return res.status(401).json({ error: "Invalid credentials" });
        const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
})

app.delete("/delete", authMiddleware, (req, res) => {
    const { id } = req.body;
    const stmt = db.prepare("DELETE FROM users WHERE id = ?");
    const result = stmt.run(id);
    if (result.changes === 0) return res.status(404).json({ error: "User not found" });
    res.json({ message: "User deleted successfully" });
})

app.post("/notes", authMiddleware, (req, res) => {
    const { title, content } = req.body;
    const userId = req.user.id;
    const stmt = db.prepare("INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)");
    const result = stmt.run(userId, title, content);
    res.json({ id: result.lastInsertRowid });
})

app.delete("/notes/:id", authMiddleware, (req, res) => {
    const noteId = req.params.id;
    const stmt = db.prepare("DELETE FROM notes WHERE id = ? AND user_id = ?");
    const result = stmt.run(noteId, req.user.id);
    if (result.changes === 0) return res.status(404).json({ error: "Note not found or not authorized" });
    res.json({ message: "Note deleted successfully" });
})

app.get("/notes", authMiddleware, (req, res) => {
    const userId = req.user.id;
    const stmt = db.prepare("SELECT * FROM notes WHERE user_id = ? AND disabled = 0");
    const notes = stmt.all(userId);
    res.json(notes);
})

app.delete("/notes/disable/:id", authMiddleware, (req, res) => {
    const noteId = req.params.id;
    const stmt = db.prepare("UPDATE notes SET disabled = 1 WHERE id = ? AND user_id = ?");
    const result = stmt.run(noteId, req.user.id);
    if (result.changes === 0) return res.status(404).json({ error: "Note not found or not authorized" });
    res.json({ message: "Note disabled successfully" });
})

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));