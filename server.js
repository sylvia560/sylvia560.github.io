const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt'); // Add bcrypt for hashing

const app = express();
app.use(cors());
app.use(bodyParser.json());

let otpStore = {};
let attemptsStore = {};

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'yhm5417@gmail.com',
        pass: 'gmzuvpsxkcwpkdwk'
    }
});

app.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    console.log("OTP requested for email:", email);

    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Always use string for bcrypt
    console.log("Generated OTP:", otp);

    const hashedOtp = await bcrypt.hash(otp, 10); // Hash OTP before storing
    console.log("Hashed OTP (stored in memory):", hashedOtp); 
    otpStore[email] = hashedOtp;
    attemptsStore[email] = 0; // Reset attempts

    const mailOptions = {
        from: 'yhm5417@gmail.com',
        to: email,
        subject: 'Your OTP for Editing',
        text: `Your OTP is ${otp}. It is valid for 5 minutes.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) return res.status(500).json({ message: "Failed to send OTP" });
        res.json({ message: "OTP sent successfully" });
    });
});

app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    if (!attemptsStore[email]) {
        attemptsStore[email] = 0;
    }

    const storedHashedOtp = otpStore[email];
    if (!storedHashedOtp) {
        return res.status(400).json({ message: "OTP expired or not found" });
    }

    const isMatch = await bcrypt.compare(otp, storedHashedOtp);

    if (isMatch) {
        delete otpStore[email];
        delete attemptsStore[email];
        return res.json({ message: "OTP verified successfully!" });
    } else {
        attemptsStore[email] += 1;
        if (attemptsStore[email] >= 3) {
            return res.status(403).json({ message: "Failed to verify OTP!" });
        }
        return res.status(400).json({ message: "Invalid OTP. Attempt " + attemptsStore[email] + " of 3" });
    }
});

app.listen(3000, () => console.log("Server running on port 3000"));
