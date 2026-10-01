const nodemailer = require("nodemailer");
const twilio = require("twilio");

const redisClient = require("../config/redis.js");
const completeRegistration = require("../utils/completeRegistration.js");


const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);


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
// SETUP SMS MFA
// =====================================================

const setupSmsMfa = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }

    const normalizedEmail = email.toLowerCase();

    const registrationData = await redisClient.get(
      `registration:${normalizedEmail}`
    );

    if (!registrationData) {
      return res.status(400).json({
        message:
          "Registration session expired. Please register again.",
      });
    }

    const parsedData = JSON.parse(registrationData);

    if (!parsedData.emailVerified) {
      return res.status(400).json({
        message: "Please verify your email first",
      });
    }

    if (!parsedData.mobileVerified) {
      return res.status(400).json({
        message: "Please verify your mobile number first",
      });
    }

    const phoneNumber =
      `${parsedData.countryCode}${parsedData.mobileNumber}`;

    // Generate MFA OTP
    const mfaOtp =
      Math.floor(
        100000 + Math.random() * 900000
      ).toString();

    await redisClient.set(
      `otp:mfa:sms:${normalizedEmail}`,
      mfaOtp,
      {
        EX: 300,
      }
    );

    parsedData.mfaMethod = "sms";
    parsedData.mfaVerified = false;

    await redisClient.set(
      `registration:${normalizedEmail}`,
      JSON.stringify(parsedData),
      {
        EX: 900,
      }
    );

    // Your Twilio trial template
    const message =
      await twilioClient.messages.create({
        body: "sms_2fa",
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phoneNumber,
      });

    

    // If Twilio template generated its own OTP,
    // extract that OTP instead.
    const otpMatch =
      message.body.match(/\b\d{6}\b/);

    if (otpMatch) {
      await redisClient.set(
        `otp:mfa:sms:${normalizedEmail}`,
        otpMatch[0],
        {
          EX: 300,
        }
      );
    }

    return res.status(200).json({
      message: "SMS MFA code sent successfully",
    });

  } catch (error) {
    console.error(
      "Setup SMS MFA Error:",
      error
    );

    return res.status(500).json({
      message: "Failed to setup SMS MFA",
    });
  }
};


// =====================================================
// VERIFY SMS MFA
// =====================================================

const verifySmsMfa = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        message: "Email and OTP are required",
      });
    }

    const normalizedEmail = email.toLowerCase();

    const registrationData = await redisClient.get(
      `registration:${normalizedEmail}`
    );

    if (!registrationData) {
      return res.status(400).json({
        message:
          "Registration session expired. Please register again.",
      });
    }

    const parsedData = JSON.parse(registrationData);

    if (!parsedData.emailVerified) {
      return res.status(400).json({
        message: "Please verify your email first",
      });
    }

    if (!parsedData.mobileVerified) {
      return res.status(400).json({
        message:
          "Please verify your mobile number first",
      });
    }

    if (parsedData.mfaMethod !== "sms") {
      return res.status(400).json({
        message:
          "SMS is not the selected MFA method",
      });
    }

    // --------------------------------
    // Attempt tracking
    // --------------------------------

    const attemptsKey =
      `registration-mfa-sms-attempts:${normalizedEmail}`;

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
        `otp:mfa:sms:${normalizedEmail}`
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
    // Get stored OTP
    // --------------------------------

    const storedOtp = await redisClient.get(
      `otp:mfa:sms:${normalizedEmail}`
    );

    if (!storedOtp) {
      return res.status(400).json({
        message:
          "MFA code expired. Please request a new code.",
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

      // Third failed attempt
      if (attemptsLeft === 0) {
        await redisClient.del(
          `otp:mfa:sms:${normalizedEmail}`
        );

        await redisClient.del(attemptsKey);

        return res.status(429).json({
          message:
            "Maximum verification attempts reached. Please register again.",
          verified: false,
          attemptsLeft: 0,
        });
      }

      const message =
        attemptsLeft === 1
          ? "Incorrect code. Please try again. You have 1 attempt left."
          : `Incorrect code. Please try again. You have ${attemptsLeft} attempts left.`;

      return res.status(400).json({
        message,
        verified: false,
        attemptsLeft,
      });
    }

    // --------------------------------
    // MFA verified
    // --------------------------------

    parsedData.mfaVerified = true;

    await redisClient.set(
      `registration:${normalizedEmail}`,
      JSON.stringify(parsedData),
      {
        EX: 900,
      }
    );

    // --------------------------------
    // Delete OTP + attempts
    // --------------------------------

    await redisClient.del(
      `otp:mfa:sms:${normalizedEmail}`
    );

    await redisClient.del(attemptsKey);

    // --------------------------------
    // FINAL USER CREATION
    // --------------------------------

    const user = await completeRegistration(
      parsedData,
      normalizedEmail
    );

    return res.status(201).json({
      message:
        "Registration completed successfully",

      verified: true,

      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        countryCode: user.countryCode,
        mobileNumber: user.mobileNumber,
      },
    });

  } catch (error) {
    console.error(
      "Verify SMS MFA Error:",
      error
    );

    if (
      error.message ===
      "Email or mobile number is already registered"
    ) {
      return res.status(409).json({
        message: error.message,
      });
    }

    return res.status(500).json({
      message:
        "Failed to verify SMS MFA",
    });
  }
};

// =====================================================
// SETUP EMAIL MFA
// =====================================================

const setupEmailMfa = async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }

    const normalizedEmail =
      email.toLowerCase();

    const registrationData =
      await redisClient.get(
        `registration:${normalizedEmail}`
      );

    if (!registrationData) {
      return res.status(400).json({
        message:
          "Registration session expired. Please register again.",
      });
    }

    const parsedData =
      JSON.parse(registrationData);

    if (!parsedData.emailVerified) {
      return res.status(400).json({
        message:
          "Please verify your email first",
      });
    }

    if (!parsedData.mobileVerified) {
      return res.status(400).json({
        message:
          "Please verify your mobile number first",
      });
    }

    // Generate MFA OTP
    const mfaOtp =
      Math.floor(
        100000 + Math.random() * 900000
      ).toString();

    await redisClient.set(
      `otp:mfa:email:${normalizedEmail}`,
      mfaOtp,
      {
        EX: 300,
      }
    );

    parsedData.mfaMethod = "email";
    parsedData.mfaVerified = false;

    await redisClient.set(
      `registration:${normalizedEmail}`,
      JSON.stringify(parsedData),
      {
        EX: 900,
      }
    );

    await emailTransporter.sendMail({
      from: process.env.EMAIL_FROM,

      to: normalizedEmail,

      subject: "MFA Verification Code",

      text:
        `Your MFA verification code is ${mfaOtp}. ` +
        `It expires in 5 minutes.`,
    });

    return res.status(200).json({
      message:
        "Email MFA code sent successfully",
    });

  } catch (error) {
    console.error(
      "Setup Email MFA Error:",
      error
    );

    return res.status(500).json({
      message:
        "Failed to setup Email MFA",
    });
  }
};


// =====================================================
// VERIFY EMAIL MFA
// =====================================================

const verifyEmailMfa = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        message:
          "Email and OTP are required",
      });
    }

    const normalizedEmail =
      email.toLowerCase();

    const registrationData =
      await redisClient.get(
        `registration:${normalizedEmail}`
      );

    if (!registrationData) {
      return res.status(400).json({
        message:
          "Registration session expired. Please register again.",
      });
    }

    const parsedData =
      JSON.parse(registrationData);

    if (!parsedData.emailVerified) {
      return res.status(400).json({
        message:
          "Please verify your email first",
      });
    }

    if (!parsedData.mobileVerified) {
      return res.status(400).json({
        message:
          "Please verify your mobile number first",
      });
    }

    if (parsedData.mfaMethod !== "email") {
      return res.status(400).json({
        message:
          "Email is not the selected MFA method",
      });
    }

    // --------------------------------
    // Attempt tracking
    // --------------------------------

    const attemptsKey =
      `registration-mfa-email-attempts:${normalizedEmail}`;

    const attemptsData =
      await redisClient.get(attemptsKey);

    const attempts = attemptsData
      ? Number(attemptsData)
      : 0;

    // --------------------------------
    // Check maximum attempts
    // --------------------------------

    if (attempts >= 3) {
      await redisClient.del(
        `otp:mfa:email:${normalizedEmail}`
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
    // Get stored OTP
    // --------------------------------

    const storedOtp =
      await redisClient.get(
        `otp:mfa:email:${normalizedEmail}`
      );

    if (!storedOtp) {
      return res.status(400).json({
        message:
          "MFA code expired. Please request a new code.",
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

      // Third failed attempt
      if (attemptsLeft === 0) {
        await redisClient.del(
          `otp:mfa:email:${normalizedEmail}`
        );

        await redisClient.del(attemptsKey);

        return res.status(429).json({
          message:
            "Maximum verification attempts reached. Please register again.",
          verified: false,
          attemptsLeft: 0,
        });
      }

      const message =
        attemptsLeft === 1
          ? "Incorrect code. Please try again. You have 1 attempt left."
          : `Incorrect code. Please try again. You have ${attemptsLeft} attempts left.`;

      return res.status(400).json({
        message,
        verified: false,
        attemptsLeft,
      });
    }

    // --------------------------------
    // MFA verified
    // --------------------------------

    parsedData.mfaVerified = true;

    await redisClient.set(
      `registration:${normalizedEmail}`,
      JSON.stringify(parsedData),
      {
        EX: 900,
      }
    );

    // --------------------------------
    // Delete OTP + attempts
    // --------------------------------

    await redisClient.del(
      `otp:mfa:email:${normalizedEmail}`
    );

    await redisClient.del(attemptsKey);

    // --------------------------------
    // FINAL USER CREATION
    // --------------------------------

    const user =
      await completeRegistration(
        parsedData,
        normalizedEmail
      );

    return res.status(201).json({
      message:
        "Registration completed successfully",

      verified: true,

      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        countryCode: user.countryCode,
        mobileNumber: user.mobileNumber,
      },
    });

  } catch (error) {
    console.error(
      "Verify Email MFA Error:",
      error
    );

    if (
      error.message ===
      "Email or mobile number is already registered"
    ) {
      return res.status(409).json({
        message: error.message,
      });
    }

    return res.status(500).json({
      message:
        "Failed to verify Email MFA",
    });
  }
};

module.exports = {
  setupSmsMfa,
  verifySmsMfa,
  setupEmailMfa,
  verifyEmailMfa,
};