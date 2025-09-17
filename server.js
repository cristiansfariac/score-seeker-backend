// server.js with CORS fix

const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const cors = require('cors'); // REQUIRES 'cors' package

const app = express();
app.use(cors()); // USES 'cors' middleware
app.use(express.json());

const unverifiedUsers = {}; 
const verifiedUsers = {};

app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (verifiedUsers[email]) {
            return res.status(400).send('This email is already registered and verified.');
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        unverifiedUsers[email] = { 
            password: hashedPassword, 
            code: verificationCode,
            timestamp: Date.now()
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
    if (userData && userData.code === code) {
        const fifteenMinutes = 15 * 60 * 1000;
        if (Date.now() - userData.timestamp > fifteenMinutes) {
            delete unverifiedUsers[email];
            return res.status(400).send('Verification code has expired. Please register again.');
        }
        verifiedUsers[email] = { password: userData.password };
        delete unverifiedUsers[email];
        res.status(200).send('Account successfully verified! You can now log in.');
    } else {
        res.status(400).send('Invalid email or verification code.');
    }
});

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
        from: '"Score Seeker" <no-reply@scoreseeker.com>',
        to: email,
        subject: "Your Verification Code",
        text: `Welcome to Score Seeker! Your one-time verification code is: ${code}`,
        html: `<b>Welcome to Score Seeker!</b><p>Your one-time verification code is: <h2>${code}</h2></p>`
    });
    console.log("Message sent: %s", info.messageId);
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
}

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});