const express = require("express");
const nodemailer = require("nodemailer");
const cors = require("cors");
const dotenv = require("dotenv");
const path = require("path");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Load .env from root
dotenv.config({ path: path.resolve(__dirname, "../.env") });

// Debug .env
console.log("EMAIL_USER:", process.env.EMAIL_USER || "undefined");
console.log("EMAIL_PASS:", process.env.EMAIL_PASS ? "[HIDDEN]" : "undefined");
console.log("PORT:", process.env.PORT || 5000);

const app = express();
const port = process.env.PORT || 5000;

// MySQL connection (Aiven or local)
const dbConfig = {
  host: process.env.NODE_ENV === "production" ? process.env.DB_HOST : process.env.DB_HOST_LOCAL,
  port: process.env.NODE_ENV === "production" ? process.env.DB_PORT : process.env.DB_PORT_LOCAL,
  user: process.env.NODE_ENV === "production" ? process.env.DB_USER : process.env.DB_USER_LOCAL,
  password: process.env.NODE_ENV === "production" ? process.env.DB_PASS : process.env.DB_PASS_LOCAL,
  database: "mamahub_db",
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: true } : undefined,
};

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_123";

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  debug: true,
  logger: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Middleware
app.use(cors({
  origin: ["http://localhost:5173", "https://mamahub.vercel.app"],
  methods: ["GET", "POST"],
  credentials: true,
}));
app.use(express.json());

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Access token required" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// Health check
app.get("/", (req, res) => {
  res.status(200).json({ message: "MamaHub API is running!" });
});

// Test database connection
app.get("/api/test-db", async (req, res) => {
  try {
    const db = await mysql.createConnection(dbConfig);
    const [rows] = await db.execute("SELECT 1");
    await db.end();
    res.status(200).json({ message: "Database connected successfully", rows });
  } catch (error) {
    console.error("Database connection error:", error.message);
    res.status(500).json({ message: "Failed to connect to database", error: error.message });
  }
});

// Signup route with email verification
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Missing required fields: name, email, password" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  try {
    const db = await mysql.createConnection(dbConfig);
    const [existingUsers] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
    if (existingUsers.length > 0) {
      await db.end();
      return res.status(400).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
    const hashedCode = await bcrypt.hash(verificationCode, 10);

    await db.execute(
      "INSERT INTO users (name, email, password, verification_code, is_verified) VALUES (?, ?, ?, ?, ?)",
      [name, email, hashedPassword, hashedCode, false]
    );

    // Send welcome email with verification code
    const mailOptions = {
      from: `"MamaHub" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Welcome to MamaHub! Verify Your Email",
      html: `
        <h3>Welcome to MamaHub, ${name}!</h3>
        <p>Thank you for signing up. Please use the following code to verify your email:</p>
        <h2>${verificationCode}</h2>
        <p>Enter this code in the MamaHub app to complete your registration.</p>
        <p>If you didn’t sign up, please ignore this email.</p>
      `,
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      console.log("Welcome email sent:", info.response);
    } catch (emailError) {
      console.error("Email sending failed:", emailError.message);
      await db.end();
      return res.status(500).json({ message: "User registered, but failed to send verification email" });
    }

    await db.end();
    res.status(201).json({ message: "User registered successfully! Please check your email for the verification code." });
  } catch (error) {
    console.error("Signup error:", error.message);
    res.status(500).json({ message: "Failed to register user", error: error.message });
  }
});

// Verify email route
app.post("/api/verify-email", async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ message: "Missing required fields: email, code" });
  }

  try {
    const db = await mysql.createConnection(dbConfig);
    const [users] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
    if (users.length === 0) {
      await db.end();
      return res.status(404).json({ message: "User not found" });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(code, user.verification_code);
    if (!isMatch) {
      await db.end();
      return res.status(400).json({ message: "Invalid verification code" });
    }

    await db.execute("UPDATE users SET is_verified = true, verification_code = NULL WHERE email = ?", [email]);
    await db.end();
    res.status(200).json({ message: "Email verified successfully!" });
  } catch (error) {
    console.error("Verify email error:", error.message);
    res.status(500).json({ message: "Failed to verify email", error: error.message });
  }
});

// Login route
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Missing required fields: email, password" });
  }

  try {
    const db = await mysql.createConnection(dbConfig);
    const [users] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
    if (users.length === 0) {
      await db.end();
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const user = users[0];
    if (!user.is_verified) {
      await db.end();
      return res.status(403).json({ message: "Please verify your email before logging in" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      await db.end();
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "1h",
    });
    await db.end();
    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ message: "Failed to login", error: error.message });
  }
});

// Contact route
app.post("/api/contact", async (req, res) => {
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ message: "Missing required fields: name, email, message" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  const mailOptions = {
    from: `"${name}" <${process.env.EMAIL_USER}>`,
    to: process.env.EMAIL_USER,
    replyTo: email,
    subject: `MamaHub Contact Form - From ${name}`,
    html: `
      <h3>New Contact Message</h3>
      <p><strong>Name:</strong> ${name}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><strong>Message:</strong></p>
      <p>${message}</p>
    `,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent:", info.response);
    res.status(200).json({ message: "Email sent successfully!" });
  } catch (error) {
    console.error("Email sending failed:", error.message, error.stack);
    res.status(500).json({ message: "Failed to send email", error: error.message });
  }
});

// Add baby profile
app.post("/api/babies", authenticateToken, async (req, res) => {
  const { name, birth_date, gender } = req.body;
  if (!name || !birth_date || !gender) {
    return res.status(400).json({ message: "Missing required fields: name, birth_date, gender" });
  }

  try {
    const db = await mysql.createConnection(dbConfig);
    await db.execute(
      "INSERT INTO babies (user_id, name, birth_date, gender) VALUES (?, ?, ?, ?)",
      [req.user.userId, name, birth_date, gender]
    );
    await db.end();
    res.status(201).json({ message: "Baby profile added!" });
  } catch (error) {
    console.error("Add baby error:", error.message);
    res.status(500).json({ message: "Failed to add baby profile", error: error.message });
  }
});

// Get user data
app.get("/api/user", authenticateToken, async (req, res) => {
  try {
    const db = await mysql.createConnection(dbConfig);
    const [users] = await db.execute("SELECT id, name, email FROM users WHERE id = ?", [req.user.userId]);
    if (users.length === 0) {
      await db.end();
      return res.status(404).json({ message: "User not found" });
    }
    await db.end();
    res.status(200).json(users[0]);
  } catch (error) {
    console.error("Get user error:", error.message);
    res.status(500).json({ message: "Failed to fetch user data", error: error.message });
  }
});

// Add schedule
app.post("/api/schedules", authenticateToken, async (req, res) => {
  const { baby_id, type, scheduled_time, notes } = req.body;
  if (!baby_id || !type || !scheduled_time) {
    return res.status(400).json({ message: "Missing required fields: baby_id, type, scheduled_time" });
  }

  try {
    const db = await mysql.createConnection(dbConfig);
    await db.execute(
      "INSERT INTO schedules (baby_id, type, scheduled_time, notes) VALUES (?, ?, ?, ?)",
      [baby_id, type, scheduled_time, notes || null]
    );
    await db.end();
    res.status(201).json({ message: "Schedule added!" });
  } catch (error) {
    console.error("Add schedule error:", error.message);
    res.status(500).json({ message: "Failed to add schedule", error: error.message });
  }
});

// Add expense
app.post("/api/expenses", authenticateToken, async (req, res) => {
  const { baby_id, category, amount, description, expense_date } = req.body;
  if (!category || !amount || !expense_date) {
    return res.status(400).json({ message: "Missing required fields: category, amount, expense_date" });
  }

  try {
    const db = await mysql.createConnection(dbConfig);
    await db.execute(
      "INSERT INTO expenses (user_id, baby_id, category, amount, description, expense_date) VALUES (?, ?, ?, ?, ?, ?)",
      [req.user.userId, baby_id || null, category, amount, description || null, expense_date]
    );
    await db.end();
    res.status(201).json({ message: "Expense added!" });
  } catch (error) {
    console.error("Add expense error:", error.message);
    res.status(500).json({ message: "Failed to add expense", error: error.message });
  }
});

// Add milestone
app.post("/api/milestones", authenticateToken, async (req, res) => {
  const { baby_id, title, description, milestone_date, photo_url } = req.body;
  if (!baby_id || !title || !milestone_date) {
    return res.status(400).json({ message: "Missing required fields: baby_id, title, milestone_date" });
  }

  try {
    const db = await mysql.createConnection(dbConfig);
    await db.execute(
      "INSERT INTO milestones (baby_id, title, description, milestone_date, photo_url) VALUES (?, ?, ?, ?, ?)",
      [baby_id, title, description || null, milestone_date, photo_url || null]
    );
    await db.end();
    res.status(201).json({ message: "Milestone added!" });
  } catch (error) {
    console.error("Add milestone error:", error.message);
    res.status(500).json({ message: "Failed to add milestone", error: error.message });
  }
});

// Add daily read
app.post("/api/daily_reads", authenticateToken, async (req, res) => {
  const { title, content, published_date } = req.body;
  if (!title || !content || !published_date) {
    return res.status(400).json({ message: "Missing required fields: title, content, published_date" });
  }

  try {
    const db = await mysql.createConnection(dbConfig);
    await db.execute(
      "INSERT INTO daily_reads (title, content, published_date) VALUES (?, ?, ?)",
      [title, content, published_date]
    );
    await db.end();
    res.status(201).json({ message: "Daily read added!" });
  } catch (error) {
    console.error("Add daily read error:", error.message);
    res.status(500).json({ message: "Failed to add daily read", error: error.message });
  }
});

// Get daily reads
app.get("/api/daily_reads", authenticateToken, async (req, res) => {
  try {
    const db = await mysql.createConnection(dbConfig);
    const [reads] = await db.execute("SELECT * FROM daily_reads ORDER BY published_date DESC");
    await db.end();
    res.status(200).json(reads);
  } catch (error) {
    console.error("Get daily reads error:", error.message);
    res.status(500).json({ message: "Failed to fetch daily reads", error: error.message });
  }
});

// Add scripture
app.post("/api/scriptures", authenticateToken, async (req, res) => {
  const { verse, reference } = req.body;
  if (!verse || !reference) {
    return res.status(400).json({ message: "Missing required fields: verse, reference" });
  }

  try {
    const db = await mysql.createConnection(dbConfig);
    await db.execute(
      "INSERT INTO scriptures (user_id, verse, reference) VALUES (?, ?, ?)",
      [req.user.userId, verse, reference]
    );
    await db.end();
    res.status(201).json({ message: "Scripture added!" });
  } catch (error) {
    console.error("Add scripture error:", error.message);
    res.status(500).json({ message: "Failed to add scripture", error: error.message });
  }
});

app.listen(port, () => {
  console.log(`API server running on http://localhost:${port}`);
});