const express = require("express");

const {
  login,
  forgotPassword,
  verifyResetOtp,
  resetPassword,
} = require("../controllers/loginController");

const { sendLoginMfaOtp, verifyLoginMfaOtp} = require("../controllers/loginMfaController")

const router = express.Router();


// =====================================================
// LOGIN
// =====================================================

router.post(
  "/login",
  login
);


// =====================================================
// FORGOT PASSWORD
// =====================================================

router.post(
  "/forgot-password",
  forgotPassword
);


// =====================================================
// VERIFY RESET OTP
// =====================================================

router.post(
  "/verify-reset-otp",
  verifyResetOtp
);


// =====================================================
// RESET PASSWORD
// =====================================================

router.post(
  "/reset-password",
  resetPassword
);

router.post("/login-otp",sendLoginMfaOtp)

router.post("/verify-otp",verifyLoginMfaOtp)


module.exports = router;