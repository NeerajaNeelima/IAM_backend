const User = require("../models/user.js");
const redisClient = require("../config/redis.js");

const completeRegistration = async (
  parsedData,
  normalizedEmail
) => {

  if (!parsedData.emailVerified) {
    throw new Error("Email is not verified");
  }

  if (!parsedData.mobileVerified) {
    throw new Error("Mobile number is not verified");
  }

  if (!parsedData.mfaVerified) {
    throw new Error("MFA is not verified");
  }

  const existingUser = await User.findOne({
    $or: [
      {
        email: parsedData.email,
      },
      {
        countryCode: parsedData.countryCode,
        mobileNumber: parsedData.mobileNumber,
      },
    ],
  });

  if (existingUser) {
    throw new Error(
      "Email or mobile number is already registered"
    );
  }

  const userData = {
    fullName: parsedData.fullName,
    email: parsedData.email,
    countryCode: parsedData.countryCode,
    mobileNumber: parsedData.mobileNumber,
    password: parsedData.password,

    mfaMethod: parsedData.mfaMethod,
    mfaVerified: parsedData.mfaVerified,
  };

  // Store authenticator secret only
  // when authenticator is selected.
  if (
    parsedData.mfaMethod === "authenticator"
  ) {
    userData.authenticatorSecret =
      parsedData.authenticatorSecret;

    userData.authenticatorEnabled = true;
  }

  const user = await User.create(userData);

  // Registration is completed.
  // Delete temporary Redis data.
  await redisClient.del(
    `registration:${normalizedEmail}`
  );

  return user;
};

module.exports = completeRegistration;