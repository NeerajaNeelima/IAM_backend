const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");

require("dotenv").config();

const registerRoutes = require("./routes/registerRoutes");
const authenticatorRoutes = require("./routes/authenticatorRoutes");
const mfaRoutes =require("./routes/mfaRoutes.js");
const loginRoutes=require("./routes/loginRoutes.js")

const app = express();

app.use(
    cors({
      origin: "http://localhost:3000",
      credentials: true,
    })
  );
app.use(express.json());

app.use(cookieParser());

const PORT = process.env.PORT || 5000;

app.get("/", (req, res) => {
    res.json({
        message: "IAM Backend Server is running"
    });
});

// MongoDB connection
mongoose
    .connect(process.env.MONGODB_URI)
    .then(() => {
        console.log("MongoDB Connected Successfully");
    })
    .catch((error) => {
        console.error("MongoDB Connection Failed:", error.message);
    });

// Registration routes
app.use("/api/register", registerRoutes);
app.use("/api/authenticator", authenticatorRoutes);
app.use("/api/mfa",mfaRoutes);
app.use("/api/signin",loginRoutes);
  

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});