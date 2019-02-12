const mongoose = require('mongoose');

const { Schema } = mongoose;

const TokenSchema = new Schema({
  token: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  }
});

const Token = mongoose.model('token', TokenSchema);

module.exports = Token;