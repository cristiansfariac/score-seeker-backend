// server.js with password validation

const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const unverifiedUsers = {}; 
const verifiedUsers = {};

app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // --- NEW: Password Strength Validation ---
        const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).send('Password must be at least 8 characters long and contain at least one letter, one number, and one special character.');
        }
        // --- END of New Validation ---

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

async function sendVerificationEmail(email, code) {
    let transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
            user: 'jany.fadel22@ethereal.email',
            pass: 'Zp2GgNtAvS91datQWh'
        }
    });
    let info = await transporter.sendMail({
        from: '"Score Seeker" <no-reply@scoreseeker.com>', to: email, subject: "Your Verification Code",
        text: `Your one-time verification code is: ${code}`,
        html: `<b>Your one-time verification code is: <h2>${code}</h2></b>`
    });
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
}

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});