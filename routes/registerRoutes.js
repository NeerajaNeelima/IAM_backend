const express = require("express");

const {
    sendEmailOtp,
    verifyEmailOtp,
    sendMobileOtp,
    verifyMobileOtp
} = require("../controllers/registerController");

const router = express.Router();

// Step 1 - Send Email OTP
router.post("/send-email-otp", sendEmailOtp);

// Step 2 - Verify Email OTP
router.post("/verify-email-otp", verifyEmailOtp);

// Step 3 - Send Mobile OTP
router.post("/send-mobile-otp", sendMobileOtp);

// Step 4 - Verify Mobile OTP and create user
router.post("/verify-mobile-otp", verifyMobileOtp);

module.exports = router;