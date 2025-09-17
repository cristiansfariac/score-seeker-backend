// server.js - Final Version
// Includes Registration, Verification, and Password Reset

const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const cors = require('cors');
const crypto = require('crypto'); // Built-in Node.js module for generating tokens

const app = express();
app.use(cors());
app.use(express.json());

// --- In-Memory Storage ---
const unverifiedUsers = {}; 
const verifiedUsers = {}; 
const passwordResetTokens = {};
// -----------------------

// ===============================================
// == REGISTRATION AND VERIFICATION ENDPOINTS ==
// ===============================================

app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Password Strength Validation
        const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).send('Password must be at least 8 characters long and contain at least one letter, one number, and one special character.');
        }

        if (verifiedUsers[email]) {
            return res.status(400).send('This email is already registered and verified.');
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
        res.status(200).send('Verification code sent! Check your terminal for the preview link.');

    } catch (error) {
        console.error(error);
        res.status(500).send('Error during registration.');
    }
});

app.post('/verify', (req, res) => {
    const { email, code } = req.body;
    const userData = unverifiedUsers[email];

    if (!userData) {
        return res.status(400).send('Invalid email or verification code.');
    }

    if (userData.lockUntil && userData.lockUntil > Date.now()) {
        const remainingTime = Math.ceil((userData.lockUntil - Date.now()) / 60000);
        return res.status(429).send(`Account is locked. Please try again in ${remainingTime} minutes.`);
    }

    if (userData.code === code) {
        userData.attempts = 0;
        userData.lockUntil = null;
        verifiedUsers[email] = { password: userData.password };
        delete unverifiedUsers[email];
        res.status(200).send('Account successfully verified! Redirecting...');
    } else {
        userData.attempts += 1;
        if (userData.attempts >= 3) {
            const lockDuration = 30 * 60 * 1000;
            userData.lockUntil = Date.now() + lockDuration;
            userData.attempts = 0;
            return res.status(429).send('Too many failed attempts. Your account has been locked for 30 minutes.');
        }
        res.status(400).send(`Invalid code. You have ${3 - userData.attempts} attempts remaining.`);
    }
});

// ===============================================
// ======== PASSWORD RESET ENDPOINTS ===========
// ===============================================

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!verifiedUsers[email]) {
        return res.status(404).send('No verified account with that email address exists.');
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiration = Date.now() + 3600000; // Token valid for 1 hour

    passwordResetTokens[token] = { email, expiration };

    // ❗️ IMPORTANT: Replace this with your actual Netlify site URL
    const resetLink = `https://your-site-name.netlify.app/reset-password.html?token=${token}`;

    try {
        await sendPasswordResetEmail(email, resetLink);
        res.status(200).send('A password reset link has been sent to your email.');
    } catch (error) {
        console.error('Failed to send reset email:', error);
        res.status(500).send('Error sending password reset email.');
    }
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    const tokenData = passwordResetTokens[token];

    if (!tokenData || tokenData.expiration < Date.now()) {
        if (tokenData) delete passwordResetTokens[token];
        return res.status(400).send('Password reset token is invalid or has expired.');
    }

    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
    if (!passwordRegex.test(newPassword)) {
        return res.status(400).send('Password must be at least 8 characters long and contain at least one letter, one number, and one special character.');
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    verifiedUsers[tokenData.email].password = hashedPassword;

    delete passwordResetTokens[token];

    res.status(200).send('Password has been successfully reset. You can now log in.');
});

// ===============================================
// ========= EMAIL SENDING FUNCTIONS ===========
// ===============================================

async function sendVerificationEmail(email, code) {
    let transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
            user: 'UNIQUE_ETHEREAL_USER@ethereal.email', // ❗️ Replace with your Ethereal username
            pass: 'UNIQUE_ETHEREAL_PASSWORD'         // ❗️ Replace with your Ethereal password
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
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
            user: 'jany.fadel22@ethereal.email', // ❗️ Replace with your Ethereal username
            pass: 'Zp2GgNtAvS91datQWh'         // ❗️ Replace with your Ethereal password
        }
    });

    let info = await transporter.sendMail({
        from: '"Score Seeker" <no-reply@scoreseeker.com>',
        to: email,
        subject: "Your Password Reset Link",
        text: `You requested a password reset. Click the link to reset your password: ${resetLink}`,
        html: `<b>You requested a password reset.</b><p>Click the link below to reset your password:</p><a href="${resetLink}">${resetLink}</a><p>This link is valid for one hour.</p>`
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