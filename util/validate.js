const bcrypt = require('bcrypt');

// Validates passwords
function validatePassword(password1, password2) {
  if (password1 !== password2) {
    return 'Passwords don\'t match';
  } else if (password1.length < 8 || password1.length > 20) {
    return 'Password must be between 8 and 20 characters';
  } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])/.test(password1)) {
    return 'Password must contain one lowercase and uppercase letter, and at least one number';
  }
}

module.exports = validatePassword;