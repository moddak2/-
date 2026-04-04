'use strict';

const express = require('express');

const indexRoutes = require('./routes/index');
const uploadRoutes = require('./routes/upload');

function createApp() {
	const app = express();

	// Intentionally permissive body parsers (demo)
	app.use(express.json({ limit: '2mb' }));
	app.use(express.text({ type: '*/*', limit: '2mb' }));

	// Static uploads directory (demo)
	app.use('/uploads', express.static('public/uploads'));

	app.use('/', indexRoutes);
	app.use('/upload', uploadRoutes);

	// Minimal error handler
	// (kept simple for demo; returns error message)
	// eslint-disable-next-line no-unused-vars
	app.use((err, req, res, next) => {
		res.status(500).type('text').send(String(err && err.message ? err.message : err));
	});

	return app;
}

module.exports = { createApp };
