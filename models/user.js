const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    countryCode: {
      type: String,
      required: true,
      trim: true,
    },

    mobileNumber: {
      type: String,
      required: true,
      trim: true,
    },

    password: {
      type: String,
      required: true,
      minlength: 8,
    },

    mfaMethod: {
      type: String,
      enum: ["authenticator", "sms", "email"],
      default: null,
    },

    mfaVerified:{
      type: Boolean,
      default: false,
    },
    
    authenticatorSecret: {
      type: String,
      default: null,
    },

    authenticatorEnabled: {
      type: Boolean,
      default: false,
    },
  
  },
  {
    timestamps: true,
  }
);

const User = mongoose.model("User", userSchema);

module.exports = User;