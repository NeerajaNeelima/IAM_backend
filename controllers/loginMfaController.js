const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const twilio = require("twilio");
const speakeasy = require("speakeasy");

const User = require("../models/user.js");
const redisClient = require("../config/redis.js");

const fs = require("fs");
const path = require("path");
const Handlebars = require("handlebars");

const emailOtpTemplatePath = path.join(
    __dirname,
    "../templates/email-otp-template.hbs"
);

const emailOtpTemplateSource = fs.readFileSync(
    emailOtpTemplatePath,
    "utf8"
);

const emailOtpTemplate = Handlebars.compile(
    emailOtpTemplateSource
);


// =====================================================
// TWILIO
// =====================================================

const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);


// =====================================================
// EMAIL
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
// JWT
// =====================================================

const jwt = require("jsonwebtoken");

const generateAccessToken = (user) => {
  return jwt.sign(
    {
      userId: user._id.toString(),
      email: user.email,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || "1d",
    }
  );
};


// =====================================================
// SEND LOGIN MFA OTP
// =====================================================

const sendLoginMfaOtp = async (req, res) => {
  try {

    const loginToken = req.cookies.loginToken;
    const {selectedMethod}=req.body;
  
    if (!loginToken) {
      return res.status(400).json({
        message: "Login Session expired",
      });
    }


    // -----------------------------------------------
    // Get temporary login session
    // -----------------------------------------------

    const loginSession = await redisClient.get(
      `login-session:${loginToken}`
    );

    if (!loginSession) {
      return res.status(401).json({
        message:
          "Login session expired. Please login again.",
      });
    }


    const session = JSON.parse(loginSession);

    const {
      userId,
      email,
      mfaMethod,
    } = session;


    // -----------------------------------------------
    // Authenticator does NOT need an OTP to be sent
    // -----------------------------------------------

    if (selectedMethod === "Authenticator") {
      return res.status(200).json({
        message:
          "Enter the code from your authenticator app",
        mfaMethod: "authenticator",
      });
    }


    // -----------------------------------------------
    // Find user
    // -----------------------------------------------

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }


    // -----------------------------------------------
    // Generate OTP
    // -----------------------------------------------

    const otp = Math.floor(
      100000 + Math.random() * 900000
    ).toString();


    // -----------------------------------------------
    // EMAIL MFA
    // -----------------------------------------------

    if (selectedMethod === "Email") {

      await redisClient.set(
        `otp:login:email:${loginToken}`,
        otp,
        {
          EX: 300,
        }
      );
      const emailHtml = emailOtpTemplate({
        name: user.$clonefullName,
        otp: otp.split(""),
        
    });
    

      await emailTransporter.sendMail({
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: "Email Verification OTP",
        html: emailHtml
    });


      return res.status(200).json({
        message:
          "Login verification code sent to your email",
        mfaMethod: "email",
      });
    }


    // -----------------------------------------------
    // SMS MFA
    // -----------------------------------------------

    if (selectedMethod === "SMS") {

      const phoneNumber =
        `${user.countryCode}${user.mobileNumber}`;


      /*
       * Store the generated OTP first.
       *
       * If your Twilio trial template generates
       * its own OTP, we replace this below with
       * the OTP extracted from Twilio's response.
       */

      await redisClient.set(
        `otp:login:sms:${loginToken}`,
        otp,
        {
          EX: 300,
        }
      );


      const message =
        await twilioClient.messages.create({
          body: "sms_2fa",
          from:
            process.env.TWILIO_PHONE_NUMBER,
          to: phoneNumber,
        });


      // ---------------------------------------------
      // Extract Twilio generated OTP
      // ---------------------------------------------

      const otpMatch =
        message.body.match(/\b\d{6}\b/);


      if (otpMatch) {

        await redisClient.set(
          `otp:login:sms:${loginToken}`,
          otpMatch[0],
          {
            EX: 300,
          }
        );

      }


      return res.status(200).json({
        message:
          "Login verification code sent to your phone",
        mfaMethod: "sms",
      });
    }


    return res.status(400).json({
      message: "Invalid MFA method",
    });


  } catch (error) {

    console.error(
      "Send Login MFA OTP Error:",
      error
    );

    return res.status(500).json({
      message:
        "Failed to send login verification code",
    });
  }
};


// =====================================================
// VERIFY LOGIN MFA OTP
// =====================================================

const verifyLoginMfaOtp = async (req, res) => {
    try {
      const {
        otp,
        selectedMethod,
        rememberMe
      } = req.body;
  
      
  
      const loginToken = req.cookies.loginToken;
  
      // -----------------------------------------------
      // Validate input
      // -----------------------------------------------
  
      if (!loginToken || !otp) {
        return res.status(400).json({
          message: "Login token and OTP are required",
        });
      }
  
      // -----------------------------------------------
      // Get login session
      // -----------------------------------------------
  
      const loginSession = await redisClient.get(
        `login-session:${loginToken}`
      );
  
      if (!loginSession) {
        return res.status(401).json({
          message:
            "Login session expired. Please login again.",
        });
      }
  
      const session = JSON.parse(loginSession);
  
      const {
        userId,
        email,
        mfaMethod,
      } = session;
  
      // -----------------------------------------------
      // MFA ATTEMPT LIMIT
      // -----------------------------------------------
  
      const attemptsKey = `login-mfa-attempts:${loginToken}`;
  
      const attemptsData = await redisClient.get(
        attemptsKey
      );
  
      const attempts = attemptsData
        ? Number(attemptsData)
        : 0;
  
      // Already reached maximum attempts
      if (attempts >= 3) {
        await redisClient.del(
          `login-session:${loginToken}`
        );
  
        await redisClient.del(attemptsKey);
  
        return res.status(429).json({
          message:
            "Maximum verification attempts reached. Please login again.",
          verified: false,
        });
      }
  
      // -----------------------------------------------
      // Find user
      // -----------------------------------------------
  
      const user = await User.findById(userId);
  
      if (!user) {
        return res.status(404).json({
          message: "User not found",
        });
      }
  
      let isVerified = false;
  
      // =================================================
      // AUTHENTICATOR
      // =================================================
  
      if (selectedMethod === "Authenticator") {
        if (!user.authenticatorSecret) {
          return res.status(400).json({
            message:
              "Authenticator is not configured",
          });
        }
  
        isVerified = speakeasy.totp.verify({
          secret: user.authenticatorSecret,
          encoding: "base32",
          token: otp.toString(),
          window: 1,
        });
      }
  
      // =================================================
      // EMAIL
      // =================================================
  
      else if (selectedMethod === "Email") {
        const storedOtp = await redisClient.get(
          `otp:login:email:${loginToken}`
        );
  
        if (!storedOtp) {
          return res.status(400).json({
            message:
              "Verification code expired. Please request a new code.",
          });
        }
  
        isVerified =
          storedOtp === otp.toString();
  
        if (isVerified) {
          await redisClient.del(
            `otp:login:email:${loginToken}`
          );
        }
      }
  
      // =================================================
      // SMS
      // =================================================
  
      else if (selectedMethod === "SMS") {
        const storedOtp = await redisClient.get(
          `otp:login:sms:${loginToken}`
        );
  
        if (!storedOtp) {
          return res.status(400).json({
            message:
              "Verification code expired. Please request a new code.",
          });
        }
  
        isVerified =
          storedOtp === otp.toString();
  
        if (isVerified) {
          await redisClient.del(
            `otp:login:sms:${loginToken}`
          );
        }
      }
  
      // =================================================
      // INVALID MFA METHOD
      // =================================================
  
      else {
        return res.status(400).json({
          message: "Invalid MFA method",
        });
      }
  
      // =================================================
      // INVALID OTP
      // =================================================
  
      if (!isVerified) {
        const newAttempts = attempts + 1;
  
        await redisClient.set(
          attemptsKey,
          newAttempts.toString(),
          {
            EX: 300,
          }
        );
  
        const remainingAttempts =
          3 - newAttempts;
  
        // ---------------------------------------------
        // Third failed attempt
        // ---------------------------------------------
  
        if (remainingAttempts === 0) {
          await redisClient.del(
            `login-session:${loginToken}`
          );
  
          await redisClient.del(attemptsKey);
  
          // Delete any pending OTP
          await redisClient.del(
            `otp:login:email:${loginToken}`
          );
  
          await redisClient.del(
            `otp:login:sms:${loginToken}`
          );
  
          return res.status(429).json({
            message:
              "Maximum verification attempts reached. Please login again.",
            verified: false,
            attemptsLeft: 0,
          });
        }
  
        // ---------------------------------------------
        // First / second failed attempt
        // ---------------------------------------------
  
        return res.status(400).json({
          message:
            `Incorrect code. Please try again. You have ${remainingAttempts} attempts left.`,
          verified: false,
          attemptsLeft: remainingAttempts,
        });
      }
  
      // =================================================
      // MFA VERIFIED
      // =================================================
  
      session.mfaVerified = true;
  
      // =================================================
      // GENERATE FINAL JWT
      // =================================================
  
      const token = generateAccessToken(user);
  
      // =================================================
      // DELETE TEMPORARY DATA
      // =================================================
  
      await redisClient.del(
        `login-session:${loginToken}`
      );
  
      await redisClient.del(attemptsKey);


      res.cookie("access_token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite:
          process.env.NODE_ENV === "production"
            ? "none"
            : "lax",
      
        ...(rememberMe
          ? { maxAge: 30 * 24 * 60 * 60 * 1000 }
          : {}),
      });
  
  
      // =================================================
      // LOGIN SUCCESS
      // =================================================
  
      return res.status(200).json({
        message: "Login successful",
        verified: true,
        token,
  
        user: {
          id: user._id,
          fullName: user.fullName,
          email: user.email,
          countryCode: user.countryCode,
          mobileNumber: user.mobileNumber,
          mfaMethod: user.mfaMethod,
          authenticatorEnabled:
            user.authenticatorEnabled || false,
        },
      });
  
    } catch (error) {
      console.error(
        "Verify Login MFA Error:",
        error
      );
  
      return res.status(500).json({
        message:
          "Failed to verify login MFA",
      });
    }
  };


  


module.exports = {
  sendLoginMfaOtp,
  verifyLoginMfaOtp,
};