// Import User model for database operations
import { User } from "../models/user.models.js";
// Import custom API response utility for consistent response formatting
import { ApiResponse } from "../utils/api-response.js";
// Import custom API error utility for consistent error handling
import { ApiError } from "../utils/api-error.js";
// Import async handler wrapper to catch async errors automatically
import { asyncHandler } from "../utils/async-handler.js";
// Import email utility functions for sending verification and password reset emails
import {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendEmail,
} from "../utils/mail.js";
// Import jsonwebtoken library for JWT token operations
import jwt from "jsonwebtoken";

/**
 * Generate access and refresh tokens for a user
 * @param {string} userId - The user's MongoDB _id
 * @returns {Object} Object containing accessToken and refreshToken
 */
const generateAccessAndRefreshTokens = async (userId) => {
  try {
    // Find the user in the database by their ID
    const user = await User.findById(userId);
    // Generate a short-lived access token for API requests
    const accessToken = user.generateAccessToken();
    // Generate a long-lived refresh token for obtaining new access tokens
    const refreshToken = user.generateRefreshToken();

    // Save the refresh token to the user's document in the database
    user.refreshToken = refreshToken;
    // Save without running validation to avoid password validation issues
    await user.save({ validateBeforeSave: false });
    // Return both tokens
    return { accessToken, refreshToken };
  } catch (error) {
    // Throw a custom error if token generation fails
    throw new ApiError(
      500,
      "Something went wrong while generating access token",
    );
  }
};

/**
 * Register a new user
 * Route: POST /api/v1/users/register
 */
const registerUser = asyncHandler(async (req, res) => {
  // Extract user registration data from request body
  const { email, username, password, role } = req.body;

  // Check if a user with the same email or username already exists
  const existedUser = await User.findOne({
    $or: [{ username }, { email }], // MongoDB $or operator to check either field
  });

  // If user exists, throw a 409 Conflict error
  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists", []);
  }

  // Create a new user document in the database
  const user = await User.create({
    email,
    password, // Password will be hashed by pre-save middleware in the model
    username,
    isEmailVerified: false, // Email is not verified initially
  });

  // Generate a temporary token for email verification
  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  // Store the hashed token in the database for security
  user.emailVerificationToken = hashedToken;
  // Set expiration time for the verification token
  user.emailVerificationExpiry = tokenExpiry;

  // Save the updated user document with verification token
  await user.save({ validateBeforeSave: false });

  // Send verification email to the user
  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    // Generate email content with verification link
    mailgenContent: emailVerificationMailgenContent(
      user.username,
      // Create full verification URL with unhashed token
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  // Fetch the created user without sensitive fields
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry",
  );

  // If user creation failed, throw an error
  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering a user");
  }

  // Send success response with created user data
  return res
    .status(201)
    .json(
      new ApiResponse(
        200,
        { user: createdUser },
        "User registered successfully and verification email has been sent on your email",
      ),
    );
});

/**
 * Login user
 * Route: POST /api/v1/users/login
 */
const login = asyncHandler(async (req, res) => {
  // Extract login credentials from request body
  const { email, password, username } = req.body;

  // Check if email is provided
  if (!email) {
    throw new ApiError(400, " email is required");
  }

  // Find user by email in the database
  const user = await User.findOne({ email });

  // If user doesn't exist, throw error
  if (!user) {
    throw new ApiError(400, "User does not exists");
  }

  // Verify password using the model method
  const isPasswordValid = await user.isPasswordCorrect(password);

  // If password is incorrect, throw error
  if (!isPasswordValid) {
    throw new ApiError(400, "Invalid credentials");
  }

  // Generate access and refresh tokens for the authenticated user
  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id,
  );

  // Fetch user data without sensitive fields
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry",
  );

  // Configure cookie options for security
  const options = {
    httpOnly: true, // Cookie cannot be accessed by client-side JavaScript
    secure: true, // Cookie only sent over HTTPS
  };

  // Send response with cookies and user data
  return res
    .status(200)
    .cookie("accessToken", accessToken, options) // Set access token cookie
    .cookie("refreshToken", refreshToken, options) // Set refresh token cookie
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged in successfully",
      ),
    );
});

/**
 * Logout user
 * Route: POST /api/v1/users/logout
 * Requires authentication middleware
 */
const logoutUser = asyncHandler(async (req, res) => {
  // Remove refresh token from user document in database
  await User.findByIdAndUpdate(
    req.user._id, // User ID from auth middleware
    {
      $set: {
        refreshToken: "", // Clear the refresh token
      },
    },
    {
      new: true, // Return the updated document
    },
  );
  
  // Configure cookie options
  const options = {
    httpOnly: true,
    secure: true,
  };
  
  // Clear authentication cookies and send response
  return res
    .status(200)
    .clearCookie("accessToken", options) // Remove access token cookie
    .clearCookie("refreshToken", options) // Remove refresh token cookie
    .json(new ApiResponse(200, {}, "User logged out"));
});

/**
 * Get current logged-in user details
 * Route: GET /api/v1/users/current-user
 * Requires authentication middleware
 */
const getCurrentUser = asyncHandler(async (req, res) => {
  // req.user is populated by the authentication middleware
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "Current user fetched successfully"));
});

/**
 * Verify user's email address
 * Route: GET /api/v1/users/verify-email/:verificationToken
 */
const verifyEmail = asyncHandler(async (req, res) => {
  // Extract verification token from URL parameters
  const { verificationToken } = req.params;

  // Check if token is provided
  if (!verificationToken) {
    throw new ApiError(400, "Email verification token is missing");
  }

  // Hash the token to match the stored hashed version
  let hashedToken = crypto
    .createHash("sha256") // Use SHA-256 hashing algorithm
    .update(verificationToken) // Hash the token
    .digest("hex"); // Convert to hexadecimal string

  // Find user with matching token that hasn't expired
  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() }, // Token must not be expired
  });

  // If no user found or token expired, throw error
  if (!user) {
    throw new ApiError(400, "Token is invalid or expired");
  }

  // Clear verification token fields from user document
  user.emailVerificationToken = undefined;
  user.emailVerificationExpiry = undefined;

  // Mark email as verified
  user.isEmailVerified = true;
  // Save the updated user document
  await user.save({ validateBeforeSave: false });

  // Send success response
  return res.status(200).json(
    new ApiResponse(
      200,
      {
        isEmailVerified: true,
      },
      "Email is verified",
    ),
  );
});

/**
 * Resend email verification link
 * Route: POST /api/v1/users/resend-email-verification
 * Requires authentication middleware
 */
const resendEmailVerification = asyncHandler(async (req, res) => {
  // Get the current user from database
  const user = await User.findById(req.user?._id);

  // Check if user exists
  if (!user) {
    throw new ApiError(404, "User does not exist");
  }
  
  // Check if email is already verified
  if (user.isEmailVerified) {
    throw new ApiError(409, "Email is already verified");
  }

  // Generate new verification token
  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  // Update user with new verification token
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  // Save the updated user document
  await user.save({ validateBeforeSave: false });

  // Send new verification email
  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  // Send success response
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Mail has been sent to your email ID"));
});

/**
 * Refresh access token using refresh token
 * Route: POST /api/v1/users/refresh-token
 */
const refreshAccessToken = asyncHandler(async (req, res) => {
  // Get refresh token from cookies or request body
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  // Check if refresh token is provided
  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorized access");
  }

  try {
    // Verify the refresh token using the secret key
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET,
    );

    // Find user by ID from decoded token
    const user = await User.findById(decodedToken?._id);
    
    // Check if user exists
    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }

    // Verify that the token matches the one stored in database
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token in expired");
    }

    // Configure cookie options
    const options = {
      httpOnly: true,
      secure: true,
    };

    // Generate new access and refresh tokens
    const { accessToken, refreshToken: newRefreshToken } =
      await generateAccessAndRefreshTokens(user._id);

    // Update user's refresh token in database
    user.refreshToken = newRefreshToken;
    await user.save();

    // Send response with new tokens
    return res
      .status(200)
      .cookie("accessToken", accessToken, options) // Set new access token
      .cookie("refreshToken", newRefreshToken, options) // Set new refresh token
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed",
        ),
      );
  } catch (error) {
    // If any error occurs during verification, throw invalid token error
    throw new ApiError(401, "Invalid refresh token");
  }
});

/**
 * Request password reset email
 * Route: POST /api/v1/users/forgot-password
 */
const forgotPasswordRequest = asyncHandler(async (req, res) => {
  // Extract email from request body
  const { email } = req.body;

  // Find user by email
  const user = await User.findOne({ email });

  // If user doesn't exist, throw error
  if (!user) {
    throw new ApiError(404, "User does not exists", []);
  }

  // Generate temporary token for password reset
  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  // Store hashed token in user document
  user.forgotPasswordToken = hashedToken;
  user.forgotPasswordExpiry = tokenExpiry;

  // Save the updated user document
  await user.save({ validateBeforeSave: false });

  // Send password reset email with reset link
  await sendEmail({
    email: user?.email,
    subject: "Password reset request",
    mailgenContent: forgotPasswordMailgenContent(
      user.username,
      // Use frontend URL for password reset page
      `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unHashedToken}`,
    ),
  });

  // Send success response
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "Password reset mail has been sent on your mail id",
      ),
    );
});

/**
 * Reset password using reset token
 * Route: POST /api/v1/users/reset-password/:resetToken
 */
const resetForgotPassword = asyncHandler(async (req, res) => {
  // Extract reset token from URL parameters
  const { resetToken } = req.params;
  // Extract new password from request body
  const { newPassword } = req.body;

  // Hash the reset token to match stored version
  let hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Find user with matching token that hasn't expired
  const user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordExpiry: { $gt: Date.now() }, // Token must not be expired
  });

  // If no user found or token expired, throw error
  if (!user) {
    throw new ApiError(489, "Token is invalid or expired");
  }

  // Clear password reset token fields
  user.forgotPasswordExpiry = undefined;
  user.forgotPasswordToken = undefined;

  // Set new password (will be hashed by pre-save middleware)
  user.password = newPassword;
  // Save the updated user document
  await user.save({ validateBeforeSave: false });

  // Send success response
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password reset successfully"));
});

/**
 * Change current user's password
 * Route: POST /api/v1/users/change-password
 * Requires authentication middleware
 */
const changeCurrentPassword = asyncHandler(async (req, res) => {
  // Extract old and new passwords from request body
  const { oldPassword, newPassword } = req.body;

  // Get current user from database
  const user = await User.findById(req.user?._id);

  // Verify the old password is correct
  const isPasswordValid = await user.isPasswordCorrect(oldPassword);

  // If old password is incorrect, throw error
  if (!isPasswordValid) {
    throw new ApiError(400, "Invalid old Password");
  }

  // Set new password (will be hashed by pre-save middleware)
  user.password = newPassword;
  // Save the updated user document
  await user.save({ validateBeforeSave: false });

  // Send success response
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"));
});

// Export all controller functions for use in routes
export {
  registerUser,
  login,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
  forgotPasswordRequest,
  changeCurrentPassword,
  resetForgotPassword,
};