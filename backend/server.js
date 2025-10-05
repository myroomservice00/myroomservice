// server.js (baby-step auth)
// 1) setup
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json()); // lets us read JSON bodies

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// 2) pretend database (in memory for learning)
//    NOTE: this resets if you stop the server (that’s OK for now)
const USERS = []; // each item: { id, email, passwordHash, role }

// 3) health check (already had this)
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// 4) register (signup)
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, role } = req.body;

    // baby validations
    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }
    const normalizedRole = role === "cleaner" ? "cleaner" : "customer";

    // check if email exists
    const exists = USERS.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (exists) return res.status(409).json({ error: "email already registered" });

    // hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // create user
    const id = String(Date.now()); // quick id
    const user = { id, email, passwordHash, role: normalizedRole };
    USERS.push(user);

    // return safe user data
    res.status(201).json({
      id,
      email,
      role: normalizedRole
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

// 5) login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // find user
    const user = USERS.find(u => u.email.toLowerCase() === String(email).toLowerCase());
    if (!user) return res.status(401).json({ error: "invalid email or password" });

    // check password
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "invalid email or password" });

    // make token
    const token = jwt.sign(
      { sub: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "15m" } // token valid for 15 minutes
    );

    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

// 6) tiny auth middleware
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "missing token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { sub, email, role, iat, exp }
    next();
  } catch {
    return res.status(401).json({ error: "invalid or expired token" });
  }
}

// 7) protected route example
app.get("/me", requireAuth, (req, res) => {
  const me = USERS.find(u => u.id === req.user.sub);
  if (!me) return res.status(404).json({ error: "user not found" });
  res.json({ id: me.id, email: me.email, role: me.role });
});

// 8) start server
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
