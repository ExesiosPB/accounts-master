const pino = require('pino');

const logger = pino({
  safe: true,
  level: 'info',
  prettyPrint: true,
});

module.exports = logger;