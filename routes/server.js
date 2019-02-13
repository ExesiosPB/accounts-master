const router = require('express').Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const uuid = require('uuid/v4');

const logger = require('../util/logger');
const validatePassword = require('../util/validate');
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
router.get('/checkToken', generateCheckToken);
// Route o get final JWT token from check token
// NOTE: this returns a json with a JWT token
router.get('/token/:token', generateFinalToken);

router.post('/resetPassword', resetPassword);
router.get('/resetPassword', (req, res) => {
  const messages = res.getMessages();
  res.locals.messages = messages;
  res.render('resetPassword', {
    version: info.version,
  });
});

// Handle logout
router.get('/logout', handleLogout);

function checkForUser(req, res, next) {
  // If they have user, next check
  if (req.session.user) {
    next();
  } else {
    // No user to take to login page
    res.redirect('/login');
  }
}

// Redirect user to destinations
// if they have come from somewhere session.redirectUrl
// /resetPassword
// /token
function redirectUser(req, res, next) {
  // Have they come here from somewhere else
  if (req.session.redirectUrl) {
    const url = req.session.redirectUrl;
    delete req.session.redirectUrl;
    res.redirect(url);
  } else {
    // Otherwise check for user stuff
    const email = req.session.user.email;
    User.findOne({ email: email }).then((user) => {
      if (user) {
        const resetRequired = user.passwordResetRequired;
        // User needs to reset password
        if (resetRequired) {
          res.redirect('/resetPassword');
        } else {
          res.redirect('/checkToken');
        }
      } else {
        logger.info('Redirect User, user doesnt exist');
        res.redirect('/login');
      }
    }).catch((err) => {
      logger.info('Redirect user, user find error', err);
    });  
  }
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
        // Check the passwords
        bcrypt.compare(password, user.password).then((isMatch) => {
          if (isMatch) {
            // Now store the user in the session
            req.session.user = user;
            // and then redirect
            res.redirect('/');            
          } else {
            loginFailed('Password Incorrect');
          }
        }).catch((err) => {
          loginFailed('Password error');
        })

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
function generateCheckToken(req, res) {
  if (req.session.user) {
    const userEmail = req.session.user.email;

    // Check if there is already a token for this person in db
    Token.deleteMany({ email: userEmail }).then(() => {
      // Create new random token
      const token = uuid();
      
      // Save token in database
      const newTokenCollection = new Token({
        email: userEmail,
        token: token,
      }).save().then((product) => {
        // Redirect to dashboard site /auth/:TOKEN
        res.send(`<script>window.location.href = '${dashboardURL}/auth/${token}'</script>Redirecting...`);  
      }).catch((err) => {
        tokenError('Token save error', err);
      })
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

// Generates final token, removes the check token from database and returns jwt
// NOTE: This is unlike other routes it returns a JSON
function generateFinalToken(req, res) {
  const urlToken = req.params.token;
  // Find token
  Token.findOneAndRemove({ token: urlToken }).then((product) => {
    if (!product) {
      logger.error('Token delete error');
      res.status(422).json({ error: 'Token Invalid' });
    } else {
      // The JWT payload
      const payload = { email: product.email };
      // Create jwt token
      // payload, secretKey, [options, callback]
      jwt.sign(payload, 'shhh_placebranding', { expiresIn: '3h' }, (err, token) => {
        if (err) {
          res.status(422).json({ error: 'Token error'});
        } else {
          res.json({ token });
        }
      });
    }
  }).catch((err) => {
    logger.error('Token delete error', err);
    res.status(422).json(err);
  });
}

// Handles the password reset logic
// TODO: Clean this up, we have so many redirects ugh!!
function resetPassword(req, res) {
  if (req.session.user) {
    const email = req.body.email;
    const password1 = req.body.password1;
    const password2 = req.body.password2;
    // Must have all info
    if (email && password1 && password2) {
      if (req.session.user.email === email) {
        
        // Check passwords
        const passwordError = validatePassword(password1, password2);
        if (passwordError) {
          logger.info('Password error');
          res.addMessage(passwordError);
          res.redirect('/resetPassword');
        } else {
          // Encrypt password
          const saltRounds = 10;
          bcrypt.genSalt(saltRounds, (err, salt) => {
            if (err) {
              logger.info('Password salt error', err);
              res.redirect('/login');
            } else {
              bcrypt.hash(password1, salt, (hashErr, hash) => {
                if (hashErr) {
                  logger.info('Password hash error', hashErr);
                  res.redirect('/login');
                } else {
                  // Now update
                  User.findOneAndUpdate({ email }, { 
                    password: hash, 
                    passwordResetRequired: false 
                  }, { new: true }).then((product) => {
                    
                    if (product) {
                      logger.info('Password updated successfully');
                      res.addMessage('Password resetted!');
                      res.redirect('/login');
                    } else {
                      logger.info('Password update error');
                      res.redirect('/');
                    }
                  }).catch((err) => {
                    logger.info('Update user error', err);
                    res.addMessage('Update failed');
                    res.redirect('/resetPassword');
                  });
                }
              });
            }
          });
        }
      }
    } else {
      res.redirect('/login');
    }
  }
}

function handleLogout(req, res) {
  if (req.session.user) {
    logger.info('Logging user out...');
    req.session.destroy((err) => {
      if (err) {
        logger.info('Problem with logging user out', err);
        res.redirect('/');
      } else {
        logger.info('User logged out');
        res.redirect('/');
      }
    });
  } else {
    res.redirect('/');
  }
}

module.exports = router;