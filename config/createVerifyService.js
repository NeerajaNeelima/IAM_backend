require("dotenv").config();

const twilio = require("twilio");

const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

async function createService() {
  try {
    const service = await client.verify.v2.services.create({
      friendlyName: "SecureID OTP",
    });

    console.log("=================================");
    console.log("Verify Service Created");
    console.log("Service SID:", service.sid);
    console.log("=================================");
  } catch (error) {
    console.error("Error creating Verify Service:");
    console.error(error);
  }
}

createService();