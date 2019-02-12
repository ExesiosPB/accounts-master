const router = require('express').Router();

const logger = require('../util/logger');
const User = require('../models/user.model');

// we make sure that the admin page can only be accessed by admins
router.use(checkForLogin, checkForAdmin);

// Checks to see if a user has logged in
function checkForLogin(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    // No user logged in so redirect them to login
    // not outside admin page
    res.redirect('/');
  }
}

// Checks to see if the person that has logged in is a admin
function checkForAdmin(req, res, next) {
  next();
}

module.exports = router;