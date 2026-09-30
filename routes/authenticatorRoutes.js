const express = require("express");

const {
  setupAuthenticator,
  verifyAuthenticator,
} = require("../controllers/authenticatorController");

const router = express.Router();

router.post("/setup", setupAuthenticator);

router.post("/verify", verifyAuthenticator);

module.exports = router;