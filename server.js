// server.js - Final Version
// Includes Registration, Verification, Password Reset, and Login/Logout

const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();

// --- Middleware ---
// IMPORTANT: Replace with your actual Netlify site URL for security
app.use(cors({
    origin: 'https://YOUR-NETLIFY-SITE.netlify.app', // ❗️ Replace this
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());
// ------------------

// --- In-Memory Storage ---
const unverifiedUsers = {}; 
const verifiedUsers = {}; 
const passwordResetTokens = {};

// A secret key for signing JWTs. In production, use an environment variable!
const JWT_SECRET = 'a-very-secret-and-secure-key-that-is-long';


// ===============================================
// ======== AUTHENTICATION ENDPOINTS ===========
// ===============================================

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = verifiedUsers[email];

    if (!user) {
        return res.status(401).send('Invalid email or password.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(401).send('Invalid email or password.');
    }

    const token = jwt.sign({ email: email }, JWT_SECRET, { expiresIn: '1h' });

    res.cookie('token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'none'
    });

    res.status(200).send('Login successful.');
});

app.post('/logout', (req, res) => {
    res.clearCookie('token', { httpOnly: true, secure: true, sameSite: 'none' });
    res.status(200).send('Logout successful.');
});

app.get('/profile', (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).send('Unauthorized: No token provided.');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.status(200).json({ email: decoded.email });
    } catch (error) {
        res.status(401).send('Unauthorized: Invalid token.');
    }
});


// ===============================================
// == REGISTRATION AND VERIFICATION ENDPOINTS ==
// ===============================================

app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).send('Password must meet the requirements.');
        }
        if (verifiedUsers[email]) {
            return res.status(400).send('This email is already registered.');
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        
        unverifiedUsers[email] = { 
            password: hashedPassword, 
            code: verificationCode,
            timestamp: Date.now(),
            attempts: 0,
            lockUntil: null
        };

        await sendVerificationEmail(email, verificationCode);
        res.status(200).send('Verification code sent.');
    } catch (error) {
        res.status(500).send('Error during registration.');
    }
});

app.post('/verify', (req, res) => {
    const { email, code } = req.body;
    const userData = unverifiedUsers[email];
    if (!userData) return res.status(400).send('Invalid email or code.');
    if (userData.lockUntil && userData.lockUntil > Date.now()) {
        const remainingTime = Math.ceil((userData.lockUntil - Date.now()) / 60000);
        return res.status(429).send(`Account locked. Try again in ${remainingTime} minutes.`);
    }
    if (userData.code === code) {
        verifiedUsers[email] = { password: userData.password };
        delete unverifiedUsers[email];
        res.status(200).send('Account successfully verified! Redirecting...');
    } else {
        userData.attempts += 1;
        if (userData.attempts >= 3) {
            userData.lockUntil = Date.now() + (30 * 60 * 1000);
            return res.status(429).send('Too many failed attempts. Account locked for 30 minutes.');
        }
        res.status(400).send(`Invalid code. ${3 - userData.attempts} attempts remaining.`);
    }
});


// ===============================================
// ======== PASSWORD RESET ENDPOINTS ===========
// ===============================================

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!verifiedUsers[email]) {
        return res.status(404).send('No verified account with that email exists.');
    }
    const token = crypto.randomBytes(32).toString('hex');
    passwordResetTokens[token] = { email, expiration: Date.now() + 3600000 };
    const resetLink = `https://YOUR-NETLIFY-SITE.netlify.app/reset-password.html?token=${token}`; // ❗️ Replace this
    try {
        await sendPasswordResetEmail(email, resetLink);
        res.status(200).send('A password reset link has been sent.');
    } catch (error) {
        res.status(500).send('Error sending password reset email.');
    }
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    const tokenData = passwordResetTokens[token];
    if (!tokenData || tokenData.expiration < Date.now()) {
        if (tokenData) delete passwordResetTokens[token];
        return res.status(400).send('Token is invalid or has expired.');
    }
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
    if (!passwordRegex.test(newPassword)) {
        return res.status(400).send('Password does not meet requirements.');
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    verifiedUsers[tokenData.email].password = hashedPassword;
    delete passwordResetTokens[token];
    res.status(200).send('Password has been successfully reset.');
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
            user: 'UNIQUE_ETHEREAL_USER@ethereal.email',
            pass: 'UNIQUE_ETHEREAL_PASSWORD'
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