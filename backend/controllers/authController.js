
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const userModel = require('../models/userModel.js');
const transporter = require('../config/nodemailer.js');

// Register controller
const register = async (req, res) => {

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.json({ success: false, message: "Missing Details" })
    }

    try {

        const existingUser = await userModel.findOne({ email })
        if (existingUser) {
            return res.json({ success: false, message: "User already exists" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ?
                'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        // Sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Job Listing Portal',
            text: `Hello ${name},\n\nWelcome to the Job Listing Portal! We're excited to have you on board.\n\nBest regards,\nJob Listing Portal Team`
        }

        await transporter.sendMail(mailOptions);

        res.json({ success: true });
    }
    catch (error) {
        res.json({ success: false, memessage: error.message });
    }

}

//Login controller
const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: "Email and Password are required" });
    }
    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "Invalid Email" });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.json({ success: false, message: "Invalid Password" });
        }
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ?
                'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        return res.json({ success: true });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

//logout controller
const logout = async (req, res) => {
    try {
        res.cookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ?
                'none' : 'strict',
        })

        return res.json({ success: true, message: "Logged out successfully" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

// Send Verify OTP controller to user email
const sendVerifyOtp = async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await userModel.findById(userId);
        if (user.isAccountVerified) {
            return res.json({ success: false, message: "Account already verified" });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = otp;
        user.verifyOtpExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes from now
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Hello ${user.name},\n\nYour OTP for account verification is: ${otp}\nThis OTP is valid for 10 minutes.\n\nBest regards,\nJob Listing Portal Team`
        }
        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: "Verification OTP sent to email" });

    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}

// Verify Email OTP controller
const verifiedEmail = async (req, res) => {

     const {userId, otp} = req.body;
        if(!userId || !otp){
            return res.json({success: false, message: "Missing Details"});
        }

    try {
       const user = await userModel.findById(userId);
       if(!user){
        return res.json({success: false, message: "User not found"});
       }
       if(user.verifyOtp === '' || user.verifyOtp !== otp){
        return res.json({success: false, message: "Invalid OTP"});
       }
       if(user.verifyOtpExpiry < Date.now()){
        return res.json({success: false, message: "OTP Expired"});
       }
         user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpiry = 0;
        await user.save();
        return res.json({success: true, message: "Email verified successfully"});

    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

//Check if user is authenticated
const isAuthenticated = async (req, res) => {
    try {
        return res.json({ success: true});
    } catch (error) {
        res.json
    }

}

//Send Password reset OTP
const sendResetOtp = async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.json({ success: false, message: "Email is required" });
    }
    try {
        const user = await userModel.findOne({ email});
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.resetOtp = otp;
        user.resetOtpExpiryAt = Date.now() + 10 * 60 * 1000; // 10 minutes from now
        await user.save(); 
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Hello ${user.name},\n\nYour OTP for password reset is: ${otp}\nThis OTP is valid for 10 minutes.\n\nBest regards,\nJob Listing Portal Team`
        }
        await transporter.sendMail(mailOptions);
        return res.json({ success: true, message: "Password reset OTP sent to email" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

//Reset User Password
const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.json({ success: false, message: "Missing Details" });
    }

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }
        if (user.resetOtp === '' || user.resetOtp !== otp) {
            return res.json({ success: false, message: "Invalid OTP" });
        }
        if (user.resetOtpExpiryAt < Date.now()) {
            return res.json({ success: false, message: "OTP Expired" });
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpiryAt = 0;
        await user.save();
        return res.json({ success: true, message: "Password reset successfully" });
    } catch (error) {
        return
    }
}
module.exports = { register, login, logout, sendVerifyOtp, verifiedEmail, isAuthenticated, sendResetOtp, resetPassword };