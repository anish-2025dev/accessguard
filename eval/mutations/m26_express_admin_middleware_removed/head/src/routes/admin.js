const express = require('express');
const { requireAdmin } = require('../auth');

const router = express.Router();

router.get('/users', (req, res) => res.json([]));
router.delete('/users/:id', (req, res) => res.status(204).end());

module.exports = router;
