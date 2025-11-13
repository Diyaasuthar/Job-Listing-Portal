
const verify = require('jsonwebtoken');
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: {type: String, required: true},
    email: {type: String, required: true, unique: true},
    password: {type: String, required: true},
    verifyOtp: {type: String, default: ''},
    verifyOtpExpiry: {type: Number, default: 0},
    isAccountVerified: {type: Boolean, default: false},
    resetOtp: {type: String, default: ''},
    resetOtpExpiry: {type: Number, default: 0},
    role: {type: String, enum: ['employee', 'employer'], default: 'employee'},
});

const userModel = mongoose.models.user || mongoose.model('user', userSchema);

module.exports = userModel;