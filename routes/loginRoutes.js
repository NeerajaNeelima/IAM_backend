const express = require("express");

const {
  login,
  forgotPassword,
  verifyResetOtp,
  resetPassword,
  getCurrentUser,
  logout
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

// Send MFA OTP
router.post("/login-otp",sendLoginMfaOtp)

//Verify MFA OTP
router.post("/verify-otp",verifyLoginMfaOtp)

//Get User Details
router.get("/auth-user",getCurrentUser)

//Logout
router.post("/logout", logout);


module.exports = router;