const express = require('express');

const router = express.Router();

router.get('/', (req, res) => res.json([]));
router.get('/:id', (req, res) => res.json({ id: req.params.id }));
router.post('/', (req, res) => res.status(201).json(req.body));
router.delete('/:id', (req, res) => res.status(204).end());

router.post('/:id/archive', (req, res) => res.status(202).end());

module.exports = router;
