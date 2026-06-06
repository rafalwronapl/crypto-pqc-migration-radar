const jwt = require('jsonwebtoken');

function issue(payload, privateKey) {
  return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
}

module.exports = { issue };
