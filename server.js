/*
* Placing the Brand accounts server
*/

const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo')(session);

const messages = require('./middleware/messages');
const logger = require('./util/logger');
const serverRoutes = require('./routes/server');

// Database Variables
const host = process.env.DB_HOST || 'localhost';
const port = process.env.DB_PORT || 27017;
const dbName = process.env.DB_NAME || 'pb_accounts';

const dbUrl = `mongodb://${host}:${port}/${dbName}`;

// Main Server
const serverApp = express();
const serverPort = process.env.SERVER_PORT || 3002;

// Set up session options
// See express-session details for info
let sessionDuration = 10000000;
const sessionOpts = {
  secret: 'Exesios place brand',
  saveUninitialized: true,
  resave: false,
  name: 'pb-sessionkey',
  cookie: {
    maxAge: sessionDuration,
    httpOnly: true,
    secure: true,
  },
};

logger.info('Starting the accounts server...');

// Setting up mongo (mongoose)
mongoose.Promise = global.Promise;
logger.info('Opening Mongo Connection', dbUrl);
mongoose.connect(dbUrl, {
  useNewUrlParser: true,
}).then(() => {
  logger.info('Mongo Connection Successful', dbUrl);

  // Connection successful so now launch accounts server
  launchAccountsServer();
}).catch((err) => {
  logger.error('Mongo Connection Failed', { err, dbUrl });
  process.exit();
});

function launchAccountsServer() {
  const dbConnection = mongoose.connection;

  // We store the session in the database instead 
  // of across the browser
  sessionOpts.store = new MongoStore({ 
    mongooseConnection: dbConnection
  });
  
  logger.info('Starting accounts REST API...');

  serverApp.set('trust proxy', true);

  // Parse requests of content-type: application/x-www-form-urlencoded
  serverApp.use(bodyParser.urlencoded({ extended: true }));
  // Parse requests of content-type: application/json
  serverApp.use(bodyParser.json());
  
  serverApp.use(session(sessionOpts));
  serverApp.use(messages);
  serverApp.set('view engine', 'pug');
  serverApp.use('/public', express.static(path.join(__dirname, 'public')));
  serverApp.use(serverRoutes);
  serverApp.listen(serverPort, () => {
    logger.info(`Accounts server listening on port ${serverPort}`);
  });
}
