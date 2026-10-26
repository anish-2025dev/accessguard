const express = require('express');
const { requireAdmin } = require('../auth');

const router = express.Router();

router.post('/announcements', requireAdmin, (req, res) => res.json({}));
router.put('/settings', requireAdmin, (req, res) => res.json({}));
router.patch('/quotas', requireAdmin, (req, res) => res.json({}));
router.delete('/sessions', requireAdmin, (req, res) => res.status(204).end());

module.exports = router;
