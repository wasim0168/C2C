const nodemailer = require('nodemailer');
const crypto = require('crypto');

// Configure email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

// Store OTPs temporarily (in production, use Redis)
const otpStore = new Map();

// Generate and send OTP
async function sendOTP(email) {
  // Generate 6-digit OTP
  const otp = crypto.randomInt(100000, 999999).toString();
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes expiration

  // Store OTP
  otpStore.set(email, { otp, expiresAt });

  // Send email
  try {
    await transporter.sendMail({
      from: `"Your App Name" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your Verification Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Email Verification</h2>
          <p>Your verification code is:</p>
          <div style="background: #f4f4f4; padding: 10px; border-radius: 5px; 
              font-size: 24px; font-weight: bold; letter-spacing: 2px; 
              text-align: center; margin: 20px 0;">
            ${otp}
          </div>
          <p>This code will expire in 10 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
        </div>
      `
    });
    return true;
  } catch (error) {
    console.error('Error sending OTP email:', error);
    return false;
  }
}

// Verify OTP
function verifyOTP(email, userOTP) {
  const storedOTP = otpStore.get(email);
  
  if (!storedOTP) {
    return { valid: false, message: 'No OTP found for this email' };
  }
  
  if (Date.now() > storedOTP.expiresAt) {
    otpStore.delete(email);
    return { valid: false, message: 'OTP has expired' };
  }
  
  if (userOTP !== storedOTP.otp) {
    return { valid: false, message: 'Invalid OTP' };
  }
  
  // OTP is valid, remove it from store
  otpStore.delete(email);
  return { valid: true };
}

module.exports = { sendOTP, verifyOTP };