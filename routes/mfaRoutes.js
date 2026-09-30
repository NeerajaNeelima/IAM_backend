const express = require("express");

const {
  setupSmsMfa,
  verifySmsMfa,
  setupEmailMfa,
  verifyEmailMfa,
} = require("../controllers/mfaController.js");

const router = express.Router();


// SMS MFA
router.post(
  "/sms/setup",
  setupSmsMfa
);

router.post(
  "/sms/verify",
  verifySmsMfa
);


// Email MFA
router.post(
  "/email/setup",
  setupEmailMfa
);

router.post(
  "/email/verify",
  verifyEmailMfa
);


module.exports = router;