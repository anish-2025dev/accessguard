const express = require('express');

const router = express.Router();

router.get('/health', (req, res) => res.json({ ok: true }));
router.get('/docs', (req, res) => res.send('docs'));

module.exports = router;
