const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

const redisClient = require("../config/redis.js");
const completeRegistration = require("../utils/completeRegistration.js");


// =====================================================
// SETUP AUTHENTICATOR
// =====================================================

const setupAuthenticator = async (req, res) => {
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

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `SecureID:${normalizedEmail}`,
      issuer: "SecureID",
      length: 20,
    });

    // Generate QR code
    const qrCode = await QRCode.toDataURL(
      secret.otpauth_url
    );

    // Save MFA information temporarily
    parsedData.mfaMethod = "authenticator";

    parsedData.authenticatorSecret =
      secret.base32;

    parsedData.authenticatorVerified = false;

    parsedData.mfaVerified = false;

    await redisClient.set(
      `registration:${normalizedEmail}`,
      JSON.stringify(parsedData),
      {
        EX: 900,
      }
    );

    return res.status(200).json({
      message:
        "Authenticator setup created successfully",

      qrCode,

      setupKey: secret.base32,
    });

  } catch (error) {
    console.error(
      "Authenticator Setup Error:",
      error
    );

    return res.status(500).json({
      message: "Failed to setup authenticator",
    });
  }
};


// =====================================================
// VERIFY AUTHENTICATOR
// =====================================================

const verifyAuthenticator = async (req, res) => {
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
        message: "Please verify your mobile number first",
      });
    }

    if (!parsedData.authenticatorSecret) {
      return res.status(400).json({
        message:
          "Authenticator has not been setup",
      });
    }

    // Verify TOTP
    const verified = speakeasy.totp.verify({
      secret:
        parsedData.authenticatorSecret,

      encoding: "base32",

      token: otp.toString(),

      window: 1,
    });
    
    if (!verified) {
      console.log("error")
      return res.status(400).json({
        message: "Invalid authenticator code",
        verified: false,
      });
    }

    // MFA verified
    parsedData.authenticatorVerified = true;

    parsedData.mfaVerified = true;

    await redisClient.set(
      `registration:${normalizedEmail}`,
      JSON.stringify(parsedData),
      {
        EX: 900,
      }
    );

    // NOW create MongoDB user
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
      "Verify Authenticator Error:",
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
        "Failed to verify authenticator",
    });
  }
};


module.exports = {
  setupAuthenticator,
  verifyAuthenticator,
};