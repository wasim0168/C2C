const express = require("express");
const router = express.Router();

// TEMP memory store OTP (production me DB use karo)
let otpStore = {};

router.post("/send-otp", (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.json({
            success: false,
            message: "Email required"
        });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);

    otpStore[email] = otp;

    console.log("OTP:", otp); // testing ke liye console me show hoga

    res.json({
        success: true,
        message: "OTP sent successfully"
    });
});

router.post("/resend-otp", (req, res) => {
    const { email } = req.body;

    const otp = Math.floor(100000 + Math.random() * 900000);

    otpStore[email] = otp;

    console.log("New OTP:", otp);

    res.json({
        success: true,
        message: "OTP resent successfully"
    });
});

module.exports = router;