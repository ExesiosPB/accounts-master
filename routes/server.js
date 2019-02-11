const router = require('express').Router();

const logger = require('../util/logger');
const info = require('../util/info');
const User = require('../models/user.model');

// Test route
router.get('/test', (req, res) => {
  res.send('Public accounts server');
});

router.get('/', (req, res) => {
  res.send('Hello World');
});

// When post request too '/'
router.post('/', doLogin);
router.get('/login', (req, res) => {
  console.log(req.session);
  res.render('login', {
    version: info.version,
  });
});

// Function to deal with email and password login
function doLogin(req, res) {
  const email = req.body.email;
  const password = req.body.password;
  // Check for email & password
  if (email && password) {
    // Find the user in the database
    User.findOne({ email: req.body.email }).then((user) => {
      if (user) {
        // Now store the user in the session
        req.session.user = user;
        // and then redirect
        res.redirect('/');
      } else {
        loginFailed('User not found');
      }
    }).catch((err) => {
      logger.info('db error', err);
      res.redirect('/login');
    });

  } else {
    res.redirect('/login');
  }

  // Handle failed login with redirect to login again
  // and send message to login for user
  function loginFailed(failedMessage) {
    logger.info('Login Failed', failedMessage);
    req.session.message = failedMessage;
    res.redirect('/login');
  }
}

module.exports = { router };