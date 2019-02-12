const mongoose = require('mongoose');

const { Schema } = mongoose;

const UserSchema = new Schema({
  fullname: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  passwordResetRequired: {
    type: Boolean,
    default: true
  }
});

const User = mongoose.model('user', UserSchema);

module.exports = User;