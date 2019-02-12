const router = require('express').Router();
const bcrypt = require('bcrypt');

const logger = require('../util/logger');
const User = require('../models/user.model');

// we make sure that the admin page can only be accessed by admins
router.use(checkForLogin, checkForAdmin);

// show admin home page
router.get('/', (req, res) => {
  const messages = res.getMessages();
  res.locals.messages = messages;
  res.render('admin');
});

// Create a new user
router.post('/createUser', createUser);

// Create a new user
function createUser(req, res) {
  const fullname = req.body.fullname;
  const email = req.body.email;
  const password1 = req.body.password1;
  const password2 = req.body.password2;

  // Now check for values
  if (fullname && email && password1 && password2) {
    const passwordError = validatePassword(password1, password2);
    if (passwordError) {
      createUserError('Create new user error', passwordError);
    } else {
      // Passwords valid
      // Check if a user already exists with this email
      User.findOne({ email: email }).then((user) => {
        if (user) {
          createUserError('Create new user error', 'Email already in use');
        } else {
          // Now user so create one
          const user = new User({
            fullname: fullname,
            email: email,
            password: password1,
          })

          // Now encrypt passwords
          const saltRounds = 10;
          bcrypt.genSalt(10, (err, salt) => {
            if (err) {
              createUserError(err, 'Password salt error');
            } else {
              bcrypt.hash(user.password, salt, (hashErr, hash) => {
                if (hashErr) {
                  createUserError(hashErr, 'Password hash error');
                } else {
                  user.password = hash;
                  user.save().then((product) => {
                    logger.info('User created', product);
                    res.addMessage('User created successfully!');
                    res.redirect('/admin');
                  }).catch((err) => {
                    createUserError('User save error', err);
                  });
                }
              });
            }
          });
        }
      }).catch((err) => {
        logger.error('Create new user error', err);
        res.redirect('/admin');
      });
    }
  } else {
    // Values missing
    res.redirect('/admin');
  }

  function createUserError(message, error) {
    logger.info(message, error);
    res.addMessage(error);
    res.redirect('/admin');
  }
}

function validatePassword(password1, password2) {
  if (password1 !== password2) {
    return 'Passwords don\'t match';
  } else if (password1.length < 8 || password1.length > 20) {
    return 'Password must be between 8 and 20 characters';
  } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])/.test(password1)) {
    return 'Password must contain one lowercase and uppercase letter, and at least one number';
  }
}

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
  const email = req.session.user.email;
  // Does the user have a @placingthebrand.com email
  if (/@placingthebrand.com/.test(email)) {
    next();
  } else {
    res.send('404');
  }
}

module.exports = router;