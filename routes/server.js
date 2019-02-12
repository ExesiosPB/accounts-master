const router = require('express').Router();
const jwt = require('jsonwebtoken');

const logger = require('../util/logger');
const info = require('../util/info');
const User = require('../models/user.model');
const Token = require('../models/token.model');

const dashboardURL = process.env.DASHBOARD_HOST || 'http://localhost:8080';

// Test route
router.get('/test', (req, res) => {
  res.send('Public accounts server');
});

// The first page that get's loaded, and also the page the login form sends too
// TODO: Here we can check for things like expired passwords and not licenses clicked etc
router.get('/', [checkForUser, redirectUser]);

// When post request too '/'
router.post('/', doLogin);
router.get('/login', (req, res) => {
  const messages = res.getMessages();
  // We then store as a local for use in jade file
  res.locals.messages = messages;
  res.render('login', {
    version: info.version,
  });
});

// Route to generate new check token
router.get('/token', generateToken);

function checkForUser(req, res, next) {
  // If they have user, next check
  if (req.session.user) {
    next();
  } else {
    // No user to take to login page
    res.redirect('/login');
  }
}

// Redirect user to /token to generate knew token
function redirectUser(req, res, next) {
  res.redirect('/token');
}

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
    res.addMessage(failedMessage);
    res.redirect('/login');
  }
}

// Generate new check token if user has logged in
function generateToken(req, res, next) {
  if (req.session.user) {
    const userEmail = req.session.user.email;

    // Check if there is already a token for this person in db
    Token.deleteMany({ email: userEmail }).then(() => {
      // The JWT payload
      const payload = {
        email: userEmail
      }
      // Create jwt token
      // payload, secretKey, [options, callback]
      jwt.sign(payload, 'shhh_placebranding', { expiresIn: '3h' }, (err, token) => {
        if (err) {
          tokenError('Token creation error', err);
        } else {
          // Now create new token
          const newToken = new Token({
            email: userEmail,
            token: token,
          });

          // Save new token to the database
          newToken.save().then((product) => {
            // Redirect to dashboard site
            res.send(`<script>window.location.href = '${dashboardURL}'</script>Redirecting...`);
          }).catch((err) => {
            tokenError('Token save error', err);
          });
        }
      });
    }).catch((err) => {
      tokenError('Token delete error', err);
    });
  } else {
    res.redirect('/');
  }

  function tokenError(message, error) {
    logger.error(message, error);
    res.redirect('/');
  }
}

module.exports = router;