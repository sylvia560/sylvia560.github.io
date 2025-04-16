const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(bodyParser.json());

let otpStore = {}; // Store OTPs temporarily (Use a database in production)
let attemptsStore = {}; // Store failed attempts per email

// Configure email transporter (Use a real email service in production)
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "yhm5417@gmail.com", // Replace with your email
        pass: "gmzuvpsxkcwpkdwk", // Generate an App Password for security
    },
});

// Send OTP to any email entered
app.post("/send-otp", async (req, res) => {
    const { email } = req.body;
    console.log("OTP requested for email:", email);

    const otp = Math.floor(100000 + Math.random() * 900000); // Generate a 6-digit OTP
    console.log("Generated OTP:", otp);

    otpStore[email] = otp;
    attemptsStore[email] = 0; // Reset attempts on new OTP generation

    // Send OTP via email
    const mailOptions = {
        from: "yhm5417@gmail.com",
        to: email, // Send OTP to the provided email
        subject: "Your OTP Code",
        text: `Your OTP code is ${otp}. It will expire in 5 minutes.`,
    };

    try {
        await transporter.sendMail(mailOptions);
        res.json({ message: "OTP sent successfully" });
    } catch (error) {
        console.error("Error sending OTP:", error);
        res.status(500).json({ message: "Error sending OTP", error });
    }
});

// OTP Verification
app.post("/verify-otp", (req, res) => {
    const { email, otp } = req.body;

    if (!attemptsStore[email]) {
        attemptsStore[email] = 0;
    }

    if (otpStore[email] && otpStore[email] == otp) {
        delete otpStore[email]; // OTP used, remove it
        delete attemptsStore[email]; // Reset attempts on success

        console.log("OTP verified successfully for:", email);

        return res.json({ message: "OTP verified successfully!" });
    } else {
        attemptsStore[email] += 1;
        console.warn("Invalid OTP attempt", attemptsStore[email], "for:", email);

        if (attemptsStore[email] >= 3) {
            return res.status(403).json({ message: "Failed to verify OTP!" });
        }
        return res.status(400).json({ message: "Invalid OTP. Attempt " + attemptsStore[email] + " of 3" });
    }
});


// Serve frontend files
app.use(express.static("public"));

app.listen(4000, () => console.log("Server running on port 4000"));
