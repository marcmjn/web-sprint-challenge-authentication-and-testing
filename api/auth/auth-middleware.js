const db = require('../../data/dbConfig');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../../config/secrets');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    console.log('No token provided'); // Debugging statement
    return res.status(401).json({ message: 'token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log('Invalid token', err.message); // Debugging statement
      return res.status(401).json({ message: 'token invalid' });
    }

    req.decodedJWT = decoded;
    next();
  });
};

const checkFormat = (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (username && password) {
      next();
    } else {
      next({ status: 400, message: 'username and password required' });
    }
  } catch (err) {
    next(err);
  }
};

const checkNameTaken = async (req, res, next) => {
  try {
    const { username } = req.body;
    const [user] = await db('users').where('username', username).select('username');
    if (!user) {
      next();
    } else {
      next({ status: 400, message: 'username taken' });
    }
  } catch (err) {
    next(err);
  }
};

module.exports = {
  checkFormat,
  checkNameTaken,
  restricted
};
