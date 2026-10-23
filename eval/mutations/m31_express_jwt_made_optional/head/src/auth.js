const { expressjwt } = require('express-jwt');

const requireAuth = expressjwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'], credentialsRequired: false });

function requireAdmin(req, res, next) {
  if (!req.auth || req.auth.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

module.exports = { requireAuth, requireAdmin };
