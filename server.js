
const express = require("express");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const required = ["DATABASE_URL", "JWT_SECRET", "GEMINI_API_KEY"];
for (const key of required) {
  if (!process.env[key]) {
    console.error(`Missing environment variable: ${key}`);
    process.exit(1);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS conversations (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title TEXT DEFAULT 'New conversation',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
      role TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS memories (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Login required" });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired session" });
  }
}

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected" });
  } catch {
    res.status(503).json({ status: "error", database: "unavailable" });
  }
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Enter a valid email" });
    }

    if (password.length < 10) {
      return res.status(400).json({
        error: "Password must contain at least 10 characters"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      "INSERT INTO users(email,password) VALUES($1,$2) RETURNING id,email",
      [email, hash]
    );

    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({ user, token });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Email already registered" });
    }
    console.error(error);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Incorrect email or password" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      user: { id: user.id, email: user.email },
      token
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/me", authenticate, (req, res) => {
  res.json({ user: req.user });
});

app.get("/api/chats", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,title,created_at FROM conversations
       WHERE user_id=$1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Could not load conversations" });
  }
});

app.post("/api/chats", authenticate, async (req, res) => {
  try {
    const title = String(req.body.title || "New conversation").slice(0, 100);
    const result = await pool.query(
      `INSERT INTO conversations(user_id,title)
       VALUES($1,$2) RETURNING *`,
      [req.user.id, title]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: "Could not create conversation" });
  }
});

app.get("/api/chats/:id/messages", authenticate, async (req, res) => {
  try {
    const chat = await pool.query(
      "SELECT id FROM conversations WHERE id=$1 AND user_id=$2",
      [req.params.id, req.user.id]
    );

    if (!chat.rowCount) {
      return res.status(404).json({ error: "Conversation not found" });
    }

    const result = await pool.query(
      `SELECT id,role,content,created_at FROM messages
       WHERE conversation_id=$1 ORDER BY created_at ASC`,
      [req.params.id]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Could not load messages" });
  }
});

app.post("/api/chats/:id/messages", authenticate, async (req, res) => {
  try {
    const prompt = String(req.body.message || "").trim();

    if (!prompt || prompt.length > 12000) {
      return res.status(400).json({ error: "Message must be 1-12000 characters" });
    }

    const chat = await pool.query(
      "SELECT id FROM conversations WHERE id=$1 AND user_id=$2",
      [req.params.id, req.user.id]
    );

    if (!chat.rowCount) {
      return res.status(404).json({ error: "Conversation not found" });
    }

    await pool.query(
      "INSERT INTO messages(conversation_id,role,content) VALUES($1,'user',$2)",
      [req.params.id, prompt]
    );

    const history = await pool.query(
      `SELECT role,content FROM messages
       WHERE conversation_id=$1 ORDER BY created_at DESC LIMIT 20`,
      [req.params.id]
    );

    const contents = history.rows.reverse().map(row => ({
      role: row.role === "assistant" ? "model" : "user",
      parts: [{ text: row.content }]
    }));

    const response = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key=" +
      encodeURIComponent(process.env.GEMINI_API_KEY),
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          systemInstruction: {
            parts: [{
              text: "You are RANSH, a helpful personal AI assistant. Be accurate, clear and honest. Never invent facts."
            }]
          },
          contents
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("AI provider error:", data);
      return res.status(502).json({ error: "AI service unavailable" });
    }

    const answer = data.candidates?.[0]?.content?.parts
      ?.map(part => part.text || "")
      .join("\n");

    if (!answer) {
      return res.status(502).json({ error: "AI returned an empty response" });
    }

    await pool.query(
      "INSERT INTO messages(conversation_id,role,content) VALUES($1,'assistant',$2)",
      [req.params.id, answer]
    );

    res.json({ reply: answer });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Message processing failed" });
  }
});

app.get("/api/memories", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,content,created_at FROM memories
       WHERE user_id=$1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch {
    res.status(500).json({ error: "Could not load memories" });
  }
});

app.post("/api/memories", authenticate, async (req, res) => {
  try {
    const content = String(req.body.content || "").trim();

    if (!content || content.length > 5000) {
      return res.status(400).json({ error: "Memory must be 1-5000 characters" });
    }

    const result = await pool.query(
      "INSERT INTO memories(user_id,content) VALUES($1,$2) RETURNING *",
      [req.user.id, content]
    );

    res.status(201).json(result.rows[0]);
  } catch {
    res.status(500).json({ error: "Could not save memory" });
  }
});

app.delete("/api/memories/:id", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM memories WHERE id=$1 AND user_id=$2",
      [req.params.id, req.user.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Memory not found" });
    }

    res.json({ deleted: true });
  } catch {
    res.status(500).json({ error: "Could not delete memory" });
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

async function start() {
  await initializeDatabase();
  app.listen(PORT, () => console.log(`RANSH running on port ${PORT}`));
}

start().catch(error => {
  console.error("Startup failed:", error);
  process.exit(1);
});
