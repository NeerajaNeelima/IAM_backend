const jwt = require("jsonwebtoken");

const authenticateToken = (
  req,
  res,
  next
) => {

  try {

    const authHeader =
      req.headers.authorization;


    if (!authHeader) {
      return res.status(401).json({
        message:
          "Authorization token is required",
      });
    }


    const [
      scheme,
      token,
    ] = authHeader.split(" ");


    if (
      scheme !== "Bearer" ||
      !token
    ) {
      return res.status(401).json({
        message:
          "Invalid authorization format",
      });
    }


    const decoded =
      jwt.verify(
        token,
        process.env.JWT_SECRET
      );


    req.user = decoded;


    next();

  } catch (error) {

    console.error(
      "JWT Error:",
      error.message
    );


    if (
      error.name ===
      "TokenExpiredError"
    ) {
      return res.status(401).json({
        message:
          "Token has expired",
      });
    }


    return res.status(401).json({
      message:
        "Invalid token",
    });
  }
};


module.exports =
  authenticateToken;