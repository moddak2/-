'use strict';

const express = require('express');
const fs = require('node:fs');
const path = require('node:path');

const router = express.Router();

router.get('/', (req, res) => {
	res.status(200).json({ ok: true });
});

// Vulnerable example: SQL Injection style string concatenation.
// Note: No DB is used; we only demonstrate unsafe query construction.
router.get('/sql', (req, res) => {
	const name = String(req.query.name ?? '');
	const query = `SELECT * FROM users WHERE name = '${name}'`;
	res.status(200).type('text').send(query);
});

// Vulnerable example: reflected XSS (no escaping)
router.get('/xss', (req, res) => {
	const name = String(req.query.name ?? '');
	res
		.status(200)
		.type('html')
		.send(`<html><body>Hello ${name}</body></html>`);
});

// Vulnerable example: directory traversal (no path normalization / allowlist)
router.get('/read', (req, res) => {
	const baseDir = path.join(process.cwd(), 'public', 'uploads');
	const userPath = String(req.query.path ?? '');
	const targetPath = path.join(baseDir, userPath);

	const data = fs.readFileSync(targetPath);
	res.status(200).type('application/octet-stream').send(data);
});

module.exports = router;
