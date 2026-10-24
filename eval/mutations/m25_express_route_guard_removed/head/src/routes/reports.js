const express = require('express');
const { requireAuth } = require('../auth');

const router = express.Router();

router.get('/', (req, res) => res.json([]));

module.exports = router;
