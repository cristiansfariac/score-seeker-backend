// server.js - Final Version with PostgreSQL Database Integration

const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg'); // PostgreSQL client

// --- Database Connection ---
const pool = new Pool({
    // Your personal Neon database connection string
    connectionString: "postgresql://neondb_owner:npg_UxiqyL3Ede5r@ep-solitary-block-adn42qhl-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require",
    ssl: {
        rejectUnauthorized: false
    }
});
// -------------------------

const app = express();

// --- Middleware ---
// IMPORTANT: Replace with your actual Netlify site URL for security
app.use(cors({
    origin: 'https://gilded-souffle-49d642.netlify.app', // ❗️ Replace this with your actual Netlify site URL
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());
// ------------------

// A secret key for signing JWTs. In production, use an environment variable!
const JWT_SECRET = 'a-very-secret-and-secure-key-that-is-long';


// ===============================================
// ======== DATABASE SETUP (RUN ONCE) ==========
// ===============================================

// A one-time endpoint to create your database tables.
app.get('/setup-database', async (req, res) => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                is_verified BOOLEAN DEFAULT FALSE,
                verification_code VARCHAR(10),
                verification_timestamp BIGINT,
                login_attempts INT DEFAULT 0,
                lock_until BIGINT
            );
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                token VARCHAR(255) UNIQUE NOT NULL,
                expiration BIGINT NOT NULL
            );
        `);
        res.status(200).send('Database tables created successfully!');
    } catch (err) {
        console.error('Database setup error:', err);
        res.status(500).send('Error creating database tables.');
    }
});


// ===============================================
// ======== AUTHENTICATION ENDPOINTS ===========
// ===============================================

app.post('/login', async (req, res) => {
    // This endpoint will be built next, after users are in the database.
    res.status(501).send('Login functionality not yet implemented with database.');
});

app.post('/logout', (req, res) => {
    res.clearCookie('token', { httpOnly: true, secure: true, sameSite: 'none' });
    res.status(200).send('Logout successful.');
});

app.get('/profile', (req, res) => {
    // This endpoint will be updated after login is implemented.
    res.status(501).send('Profile functionality not yet implemented with database.');
});


// ===============================================
// == REGISTRATION AND VERIFICATION ENDPOINTS ==
// ===============================================

app.post('/register', async (req, res) => {
    // This will be the first endpoint we refactor to use SQL queries.
    res.status(501).send('Registration functionality not yet implemented with database.');
});

app.post('/verify', (req, res) => {
    // This endpoint will also be refactored.
    res.status(501).send('Verification functionality not yet implemented with database.');
});


// ===============================================
// ======== PASSWORD RESET ENDPOINTS ===========
// ===============================================

app.post('/forgot-password', async (req, res) => {
    // This endpoint will be refactored.
    res.status(501).send('Forgot password functionality not yet implemented with database.');
});

app.post('/reset-password', async (req, res) => {
    // This endpoint will be refactored.
    res.status(501).send('Reset password functionality not yet implemented with database.');
});


// ===============================================
// ========= EMAIL SENDING FUNCTIONS ===========
// ===============================================

async function sendVerificationEmail(email, code) {
    let transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email', port: 587, secure: false,
        auth: {
            user: 'UNIQUE_ETHEREAL_USER@ethereal.email',
            pass: 'UNIQUE_ETHEREAL_PASSWORD'
        }
    });
    let info = await transporter.sendMail({
        from: '"Score Seeker" <no-reply@scoreseeker.com>', to: email, subject: "Your Verification Code",
        text: `Your one-time verification code is: ${code}`,
        html: `<b>Your one-time verification code is: <h2>${code}</h2></b>`
    });
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
}

async function sendPasswordResetEmail(email, resetLink) {
    let transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email', port: 587, secure: false,
        auth: {
            user: 'jany.fadel22@ethereal.email',
            pass: 'Zp2GgNtAvS91datQWh'
        }
    });
    let info = await transporter.sendMail({
        from: '"Score Seeker" <no-reply@scoreseeker.com>', to: email, subject: "Your Password Reset Link",
        text: `Click the link to reset your password: ${resetLink}`,
        html: `<p>Click the link below to reset your password:</p><a href="${resetLink}">${resetLink}</a>`
    });
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
}

// ===============================================
// ============== START SERVER =================
// ===============================================
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});