const fs        = require('fs');
const crypto    = require('crypto');
const jwt       = require('jsonwebtoken');

// Init values from env or use defaults
const KEY_DIR = process.env.KEY_DIR || 'keys';
const pub_key = fs.readFileSync(`${__dirname}/../${KEY_DIR}/auth.acme.com.pub.pem`);

exports.verify_token = (token, options = {}) => {
    return jwt.verify(token, pub_key, options);
}

exports.decode_token =(token, options = {}) => {
    return jwt.decode(token, pub_key, options);
}

exports.verify_file = (hash, payload) => {
    const digest = crypto.createHash('sha256').update(payload).digest('hex');
    return hash === digest;
}


