const express = require('express');
const { requireAuth } = require('./auth');
const items = require('./routes/items');
const admin = require('./routes/admin');
const publicRoutes = require('./routes/public');
const reports = require('./routes/reports');
const orders = require('./routes/orders').default;

const app = express();
app.use(express.json());

app.use('/public', publicRoutes);
app.use('/reports', reports);
app.use('/orders', orders);

app.use('/api', requireAuth);
app.use('/api/items', items);
app.use('/api/admin', admin);
app.use('/api/staff', require('./routes/staff'));

module.exports = app;
