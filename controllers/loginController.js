const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");

const User = require("../models/user.js");
const redisClient = require("../config/redis.js");


// =====================================================
// EMAIL TRANSPORTER
// =====================================================

const emailTransporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT),
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});


// =====================================================
// CREATE JWT TOKEN
// =====================================================

const generateAccessToken = (user) => {
  return jwt.sign(
    {
      userId: user._id.toString(),
      email: user.email,
    },
    process.env.JWT_SECRET,
    {
      expiresIn:
        process.env.JWT_EXPIRES_IN || "1d",
    }
  );
};


// =====================================================
// LOGIN
// =====================================================

const login = async (req, res) => {
  try {
    const {
      email,
      password,
     
    } = req.body;


    // -----------------------------------------------
    // Validate input
    // -----------------------------------------------

    if (!email || !password) {
      return res.status(400).json({
        message:
          "Email and password are required",
      });
    }


    const normalizedEmail =
      email.trim().toLowerCase();


    // -----------------------------------------------
    // Find user
    // -----------------------------------------------

    const user = await User.findOne({
      email: normalizedEmail,
    }).select("+password");


    if (!user) {
      return res.status(401).json({
        message:
          "Invalid email or password",
      });
    }


    // -----------------------------------------------
    // Compare password
    // -----------------------------------------------

    const isPasswordCorrect =
      await bcrypt.compare(
        password,
        user.password
      );


    if (!isPasswordCorrect) {
      return res.status(401).json({
        message:
          "Invalid email or password",
      });
    }


    // -----------------------------------------------
    // Check MFA
    // -----------------------------------------------


      const mfaMethod = user.mfaMethod;

      if (mfaMethod) {
        const loginToken = crypto.randomBytes(32).toString("hex");
      
        await redisClient.set(
          `login-session:${loginToken}`,
          JSON.stringify({
            userId: user._id.toString(),
            email: user.email,
            mfaMethod,
            mfaVerified: false,
          }),
          {
            EX: 600,
          }
        );

        res.cookie("loginToken", loginToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite:
              process.env.NODE_ENV === "production"
                ? "none"
                : "lax",
            maxAge: 10 * 60 * 1000,
            path: "/",
          });

          
        return res.status(200).json({
          message: "Password verified. MFA verification required.",
          requiresMfa: true,
          mfaMethod,
          user: {
            fullName: user.fullName,
            email: user.email,
            countryCode:
              user.countryCode,
            mobileNumber:
              user.mobileNumber,
          },
        });
      }


    // -----------------------------------------------
    // Generate JWT
    // -----------------------------------------------

    const token =
      generateAccessToken(user);


    // -----------------------------------------------
    // Successful login
    // -----------------------------------------------

    return res.status(200).json({
      message:
        "Login successful",

      requiresMfa: false,

      token,

      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        countryCode:
          user.countryCode,
        mobileNumber:
          user.mobileNumber,

        authenticatorEnabled:
          user.authenticatorEnabled ||
          false,
      },
    });

  } catch (error) {

    console.error(
      "Login Error:",
      error
    );

    return res.status(500).json({
      message:
        "Login failed",
    });
  }
};


// =====================================================
// FORGOT PASSWORD
// =====================================================

const forgotPassword = async (req, res) => {
  try {

    const { email } = req.body;


    if (!email) {
      return res.status(400).json({
        message:
          "Email is required",
      });
    }


    const normalizedEmail =
      email.trim().toLowerCase();


    const user =
      await User.findOne({
        email: normalizedEmail,
      });


    if (!user) {
      return res.status(200).json({
        message:
          "If an account exists with this email, a password reset code has been sent.",
      });
    }


    // Generate OTP
    const resetOtp =
      crypto.randomInt(
        100000,
        1000000
      ).toString();


    // Store OTP in Redis
    await redisClient.set(
      `otp:password-reset:${normalizedEmail}`,
      resetOtp,
      {
        EX: 300,
      }
    );


    // Send email
    await emailTransporter.sendMail({
      from: process.env.EMAIL_FROM,

      to: normalizedEmail,

      subject:
        "SecureID Password Reset Code",

      text:
        `Your SecureID password reset code is ${resetOtp}. ` +
        `This code expires in 5 minutes. ` +
        `If you did not request a password reset, you can ignore this email.`,
    });


    return res.status(200).json({
      message:
        "If an account exists with this email, a password reset code has been sent.",
    });

  } catch (error) {

    console.error(
      "Forgot Password Error:",
      error
    );

    return res.status(500).json({
      message:
        "Unable to process password reset request",
    });
  }
};


// =====================================================
// VERIFY RESET OTP
// =====================================================

const verifyResetOtp = async (
  req,
  res
) => {

  try {

    const {
      email,
      otp,
    } = req.body;


    if (!email || !otp) {
      return res.status(400).json({
        message:
          "Email and OTP are required",
      });
    }


    const normalizedEmail =
      email.trim().toLowerCase();


    const user =
      await User.findOne({
        email: normalizedEmail,
      });


    if (!user) {
      return res.status(400).json({
        message:
          "Invalid or expired OTP",
      });
    }


    const storedOtp =
      await redisClient.get(
        `otp:password-reset:${normalizedEmail}`
      );


    if (!storedOtp) {
      return res.status(400).json({
        message:
          "OTP expired. Please request a new OTP.",
      });
    }


    if (
      storedOtp !==
      otp.toString()
    ) {
      return res.status(400).json({
        message:
          "Invalid OTP",
      });
    }


    // Generate reset token
    const resetToken =
      crypto.randomBytes(32).toString("hex");


    await redisClient.set(
      `password-reset-token:${resetToken}`,
      normalizedEmail,
      {
        EX: 600,
      }
    );


    // Delete OTP
    await redisClient.del(
      `otp:password-reset:${normalizedEmail}`
    );


    return res.status(200).json({
      message:
        "OTP verified successfully",

      verified: true,

      resetToken,
    });

  } catch (error) {

    console.error(
      "Verify Reset OTP Error:",
      error
    );

    return res.status(500).json({
      message:
        "Failed to verify reset OTP",
    });
  }
};


// =====================================================
// RESET PASSWORD
// =====================================================

const resetPassword = async (
  req,
  res
) => {

  try {

    const {
      resetToken,
      newPassword,
      confirmPassword,
    } = req.body;


    if (
      !resetToken ||
      !newPassword ||
      !confirmPassword
    ) {
      return res.status(400).json({
        message:
          "Reset token, new password and confirm password are required",
      });
    }


    if (
      newPassword !==
      confirmPassword
    ) {
      return res.status(400).json({
        message:
          "Passwords do not match",
      });
    }


    if (newPassword.length < 8) {
      return res.status(400).json({
        message:
          "Password must be at least 8 characters",
      });
    }


    // Get email from Redis
    const normalizedEmail =
      await redisClient.get(
        `password-reset-token:${resetToken}`
      );


    if (!normalizedEmail) {
      return res.status(400).json({
        message:
          "Reset session expired. Please request a new password reset.",
      });
    }


    const user =
      await User.findOne({
        email: normalizedEmail,
      });


    if (!user) {
      return res.status(404).json({
        message:
          "User not found",
      });
    }


    // Hash password
    const hashedPassword =
      await bcrypt.hash(
        newPassword,
        10
      );


    user.password =
      hashedPassword;


    await user.save();


    // Delete reset token
    await redisClient.del(
      `password-reset-token:${resetToken}`
    );


    return res.status(200).json({
      message:
        "Password reset successfully",
    });

  } catch (error) {

    console.error(
      "Reset Password Error:",
      error
    );

    return res.status(500).json({
      message:
        "Failed to reset password",
    });
  }
};


export const getCurrentUser = async (req, res) => {
  try {
    const token = req.cookies?.access_token;

    if (!token) {
      return res.status(401).json({
        authenticated: false,
        message: "Not authenticated",
      });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    const user = await User.findById(decoded.userId).select(
      "-password"
    );

    if (!user) {
      return res.status(401).json({
        authenticated: false,
        message: "User not found",
      });
    }

    return res.status(200).json({
      authenticated: true,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        countryCode: user.countryCode,
        mobileNumber: user.mobileNumber,
      },
    });

  } catch (error) {
    console.error("Get current user error:", error);

    return res.status(401).json({
      authenticated: false,
      message: "Invalid or expired session",
    });
  }
};


module.exports = {
  login,
  forgotPassword,
  verifyResetOtp,
  resetPassword,
};