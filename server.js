const express = require("express");
const mysql = require("mysql2");
const path = require("path");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public"));

// Create a MySQL connection pool
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Home Page (Login Page)
app.get("/", (req, res) => {
  res.render("login");
});

// Register Page
app.get("/register", (req, res) => {
  res.render("register");
});

// Register User
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
  db.query(sql, [username, email, hashedPassword], (err, result) => {
    if (err) {
      console.error("Error inserting user:", err);
      return res.status(500).send("Error registering user");
    }
    res.render("success", {
      message: "Registration Successful!",
      actionMessage: "You have successfully registered. Please login to continue.",
      messageType: "message-success",
    });
  });
});

// Login User
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const sql = "SELECT * FROM users WHERE username = ?";
  db.query(sql, [username], async (err, results) => {
    if (err) {
      console.error("Error fetching user:", err);
      return res.status(500).send("Error logging in");
    }

    if (results.length === 0) {
      // If no user is found, display an error message
      return res.render("success", {
        message: "Invalid Login Attempt!",
        actionMessage: "Invalid username or password. Please register if you don't have an account.",
        messageType: "message-error", // Negative message
      });
    }

    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      // If the password doesn't match, display an error message
      return res.render("success", {
        message: "Invalid Login Attempt!",
        actionMessage: "Invalid username or password. Please try again or register if you don't have an account.",
        messageType: "message-error", // Negative message
      });
    }

    // If login is successful, render the success page with the login message
    res.render("success", {
      message: "Login Successful!",
      actionMessage: "You are now logged in. Welcome back!",
      messageType: "message-success", // Positive message
    });
  });
});

// Forgot Password Page
app.get("/forgot-password", (req, res) => {
  res.render("forgot-password");
});

// Forgot Password Logic
app.post("/forgot-password", async (req, res) => {
  const { email, newPassword } = req.body;
  const hashedPassword = await bcrypt.hash(newPassword, 10);

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], (err, result) => {
    if (err) {
      console.error("Error fetching user:", err);
      return res.status(500).send("Error resetting password");
    }

    if (result.length === 0) {
      return res.render("forgot-password", {
        error: "Email not found. Please register or provide a valid email.",
        messageType: "message-error", // Negative message
      });
    }

    const updateSql = "UPDATE users SET password = ? WHERE email = ?";
    db.query(updateSql, [hashedPassword, email], (updateErr, updateResult) => {
      if (updateErr) {
        console.error("Error updating password:", updateErr);
        return res.status(500).send("Error updating password");
      }

      res.render("success", {
        message: "Password Reset Successful!",
        actionMessage: "Your password has been reset. You can now log in with the new password.",
        messageType: "message-success", // Positive message
      });
    });
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
