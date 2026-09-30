const bcrypt = require("bcryptjs")
const nodemailer = require("nodemailer")
const twilio = require("twilio")
const axios = require("axios");

const User = require("../models/user.js")
const redisClient = require("../config/redis.js")

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

// --------------------------------------------------
// Email configuration
// --------------------------------------------------

const emailTransporter = nodemailer.createTransport({
  host: "sandbox.smtp.mailtrap.io",
  port: 2525,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// --------------------------------------------------
// Twilio configuration
// --------------------------------------------------

const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// --------------------------------------------------
// Generate 6 digit OTP
// --------------------------------------------------

const generateOtp = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// ==================================================
// SEND EMAIL OTP
// ==================================================

const sendEmailOtp = async (req, res) => {
  try {
    const {
      fullName,
      email,
      countryCode,
      mobileNumber,
      password,
    } = req.body;

    // -----------------------------
    // Validate request
    // -----------------------------

    if (
      !fullName ||
      !email ||
      !countryCode ||
      !mobileNumber ||
      !password
    ) {
      return res.status(400).json({
        message: "All fields are required",
      });
    }

    // -----------------------------
    // Check password length
    // -----------------------------

    if (password.length < 8) {
      return res.status(400).json({
        message: "Password must contain at least 8 characters",
      });
    }

    // -----------------------------
    // Check existing user
    // -----------------------------

    const existingUser = await User.findOne({
      $or: [
        { email: email.toLowerCase() },
        {
          countryCode,
          mobileNumber,
        },
      ],
    });

    if (existingUser) {
      return res.status(409).json({
        message: "Email or mobile number is already registered",
      });
    }

    // -----------------------------
    // Generate OTP
    // -----------------------------

    const otp = generateOtp();

    // -----------------------------
    // Hash password
    // -----------------------------

    const hashedPassword = await bcrypt.hash(password, 10);

    // -----------------------------
    // Store registration data
    // temporarily in Redis
    // -----------------------------

    // Temporary registration data
    const registrationData = {
      fullName,
      email: email,
      countryCode,
      mobileNumber,
      password: hashedPassword,

      emailVerified: false,
      mobileVerified: false,

      mfaMethod: null,
      mfaVerified: false,

      authenticatorSecret: null,
      authenticatorVerified: false,
    };


    await redisClient.set(
      `registration:${email.toLowerCase()}`,
      JSON.stringify(registrationData),
      {
        EX: 900,
      }
    );

    // -----------------------------
    // Store email OTP
    // 5 minutes
    // -----------------------------

    await redisClient.set(
      `otp:email:${email.toLowerCase()}`,
      otp,
      {
        EX: 300,
      }
    );

    // -----------------------------
    // Send email
    // -----------------------------
    
    const emailHtml = emailOtpTemplate({
        name: fullName,
        otp: otp.split(""),
        
    });
    
    await emailTransporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Email Verification OTP",
        html: emailHtml
    });

    return res.status(200).json({
      message: "Email OTP sent successfully",
    });
  } catch (error) {
    console.error("Send Email OTP Error:", error);

    return res.status(500).json({
      message: "Failed to send email OTP",
    });
  }
};

// ==================================================
// VERIFY EMAIL OTP
// ==================================================

const verifyEmailOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    console.log("email", email, otp);

    if (!email || !otp) {
      return res.status(400).json({
        message: "Email and OTP are required",
      });
    }

    const normalizedEmail = email.toLowerCase();

    // --------------------------------
    // Attempt tracking
    // --------------------------------

    const attemptsKey =
      `registration-email-attempts:${normalizedEmail}`;

    const attemptsData = await redisClient.get(
      attemptsKey
    );

    const attempts = attemptsData
      ? Number(attemptsData)
      : 0;

    // --------------------------------
    // Check maximum attempts
    // --------------------------------

    if (attempts >= 3) {
      await redisClient.del(
        `otp:email:${normalizedEmail}`
      );

      await redisClient.del(attemptsKey);

      return res.status(429).json({
        message:
          "Maximum verification attempts reached. Please register again.",
        verified: false,
        attemptsLeft: 0,
      });
    }

    // --------------------------------
    // Get OTP from Redis
    // --------------------------------

    const storedOtp = await redisClient.get(
      `otp:email:${normalizedEmail}`
    );

    if (!storedOtp) {
      return res.status(400).json({
        message: "OTP expired or not found",
      });
    }

    // --------------------------------
    // Compare OTP
    // --------------------------------

    if (storedOtp !== otp.toString()) {
      const newAttempts = attempts + 1;
      const attemptsLeft = 3 - newAttempts;

      await redisClient.set(
        attemptsKey,
        newAttempts.toString(),
        {
          EX: 900,
        }
      );

      if (attemptsLeft === 0) {
        await redisClient.del(
          `otp:email:${normalizedEmail}`
        );

        await redisClient.del(attemptsKey);

        return res.status(429).json({
          message:
            "Maximum verification attempts reached. Please register again.",
          verified: false,
          attemptsLeft: 0,
        });
      }

      const attemptMessage =
        attemptsLeft === 1
          ? "Incorrect code. Please try again. You have 1 attempt left."
          : `Incorrect code. Please try again. You have ${attemptsLeft} attempts left.`;

      return res.status(400).json({
        message: attemptMessage,
        verified: false,
        attemptsLeft,
      });
    }

    // --------------------------------
    // Get registration data
    // --------------------------------

    const registrationData = await redisClient.get(
      `registration:${normalizedEmail}`
    );

    if (!registrationData) {
      return res.status(400).json({
        message:
          "Registration session expired. Please register again.",
      });
    }

    const parsedData = JSON.parse(
      registrationData
    );

    // --------------------------------
    // Mark email verified
    // --------------------------------

    parsedData.emailVerified = true;

    // --------------------------------
    // Update Redis
    // --------------------------------

    await redisClient.set(
      `registration:${normalizedEmail}`,
      JSON.stringify(parsedData),
      {
        EX: 900,
      }
    );

    // --------------------------------
    // Delete used OTP + attempts
    // --------------------------------

    await redisClient.del(
      `otp:email:${normalizedEmail}`
    );

    await redisClient.del(attemptsKey);

    return res.status(200).json({
      message: "Email verified successfully",
      verified: true,
    });

  } catch (error) {
    console.error(
      "Verify Email OTP Error:",
      error
    );

    return res.status(500).json({
      message: "Failed to verify email OTP",
    });
  }
};

// ==================================================
// SEND MOBILE OTP
// ==================================================

const sendMobileOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }

    const normalizedEmail = email.toLowerCase();

    const countryCode = "+91";
    const mobileNumber = "9346571625";

    // -----------------------------
    // Get registration data
    // -----------------------------

    const registrationData = await redisClient.get(
      `registration:${normalizedEmail}`
    );

    if (!registrationData) {
      return res.status(400).json({
        message: "Registration session expired",
      });
    }

    const parsedData = JSON.parse(registrationData);

    // -----------------------------
    // Email must be verified first
    // -----------------------------

    if (!parsedData.emailVerified) {
      return res.status(400).json({
        message: "Please verify your email first",
      });
    }


    // -----------------------------
    // Send SMS
    // -----------------------------

    const phoneNumber = `${countryCode}${mobileNumber}`;

    
    const message = await twilioClient.messages.create({
      body: "sms_2fa",
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phoneNumber,
    });
    
    console.log("Twilio Message:", message);

    // -----------------------------
    // Extract OTP from Twilio body
    // Example:
    // "Your verification code is 482913.
    //  It expires in 5 minutes."
    // -----------------------------

    const otpMatch = message.body.match(/\b\d{6}\b/);

    if (!otpMatch) {
      console.error(
        "Could not extract OTP from Twilio message:",
        message.body
      );

      return res.status(500).json({
        message: "Could not extract OTP from SMS",
      });
    }

    const otp = otpMatch[0];

    console.log("Extracted OTP:", otp);

    // -----------------------------
    // Store OTP in Redis
    // Expires after 5 minutes
    // -----------------------------

    await redisClient.set(
      `otp:mobile:${phoneNumber}`,
      otp,
      {
        EX: 300,
      }
    );

    console.log(
      `OTP stored in Redis for ${phoneNumber}`
    );

    return res.status(200).json({
      message: "Mobile OTP sent successfully",
    });

  } catch (error) {
    console.error("Send Mobile OTP Error:", error);

    return res.status(500).json({
      message: "Failed to send mobile OTP",
    });
  }
};

// ==================================================
// VERIFY MOBILE OTP
// ==================================================

const verifyMobileOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        message: "Email and OTP are required",
      });
    }

    const normalizedEmail = email.toLowerCase();

    // --------------------------------
    // Get registration data
    // --------------------------------

    const registrationData = await redisClient.get(
      `registration:${normalizedEmail}`
    );

    if (!registrationData) {
      return res.status(400).json({
        message:
          "Registration session expired. Please register again.",
      });
    }

    const parsedData = JSON.parse(
      registrationData
    );

    // --------------------------------
    // Email must be verified first
    // --------------------------------

    if (!parsedData.emailVerified) {
      return res.status(400).json({
        message: "Please verify your email first",
      });
    }

    // --------------------------------
    // Get mobile number
    // --------------------------------

    const phoneNumber =
      `${parsedData.countryCode}${parsedData.mobileNumber}`;

    // --------------------------------
    // Attempt tracking
    // --------------------------------

    const attemptsKey =
      `registration-mobile-attempts:${normalizedEmail}`;

    const attemptsData = await redisClient.get(
      attemptsKey
    );

    const attempts = attemptsData
      ? Number(attemptsData)
      : 0;

    // --------------------------------
    // Check maximum attempts
    // --------------------------------

    if (attempts >= 3) {
      await redisClient.del(
        `otp:mobile:${phoneNumber}`
      );

      await redisClient.del(attemptsKey);

      return res.status(429).json({
        message:
          "Maximum verification attempts reached. Please register again.",
        verified: false,
        attemptsLeft: 0,
      });
    }

    // --------------------------------
    // Get OTP from Redis
    // --------------------------------

    const storedOtp = await redisClient.get(
      `otp:mobile:${phoneNumber}`
    );

    if (!storedOtp) {
      return res.status(400).json({
        message: "OTP expired or not found",
      });
    }

    // --------------------------------
    // Compare OTP
    // --------------------------------

    if (storedOtp !== otp.toString()) {
      const newAttempts = attempts + 1;
      const attemptsLeft = 3 - newAttempts;

      await redisClient.set(
        attemptsKey,
        newAttempts.toString(),
        {
          EX: 900,
        }
      );

      // --------------------------------
      // Third failed attempt
      // --------------------------------

      if (attemptsLeft === 0) {
        await redisClient.del(
          `otp:mobile:${phoneNumber}`
        );

        await redisClient.del(attemptsKey);

        return res.status(429).json({
          message:
            "Maximum verification attempts reached. Please register again.",
          verified: false,
          attemptsLeft: 0,
        });
      }

      const attemptMessage =
        attemptsLeft === 1
          ? "Incorrect code. Please try again. You have 1 attempt left."
          : `Incorrect code. Please try again. You have ${attemptsLeft} attempts left.`;

      return res.status(400).json({
        message: attemptMessage,
        verified: false,
        attemptsLeft,
      });
    }

    // --------------------------------
    // Mark mobile as verified
    // --------------------------------

    parsedData.mobileVerified = true;

    // --------------------------------
    // Save updated registration data
    // --------------------------------

    await redisClient.set(
      `registration:${normalizedEmail}`,
      JSON.stringify(parsedData),
      {
        EX: 900,
      }
    );

    // --------------------------------
    // Delete used OTP + attempts
    // --------------------------------

    await redisClient.del(
      `otp:mobile:${phoneNumber}`
    );

    await redisClient.del(attemptsKey);

    return res.status(200).json({
      message:
        "Mobile number verified successfully",
      verified: true,
    });

  } catch (error) {
    console.error(
      "Verify Mobile OTP Error:",
      error
    );

    return res.status(500).json({
      message:
        "Failed to verify mobile OTP",
    });
  }
};

module.exports = {
    sendEmailOtp,
    verifyEmailOtp,
    sendMobileOtp,
    verifyMobileOtp
};