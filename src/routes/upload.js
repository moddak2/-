'use strict';

const express = require('express');
const fs = require('node:fs');
const path = require('node:path');

const router = express.Router();

// Vulnerable example: insecure file upload
// - No file type/extension validation
// - Filename is taken from user input (path traversal possible)
router.post('/', (req, res) => {
	const uploadsDir = path.join(process.cwd(), 'public', 'uploads');
	fs.mkdirSync(uploadsDir, { recursive: true });

	const filename = String(req.query.filename ?? 'upload.bin');
	const targetPath = path.join(uploadsDir, filename);

	const body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
	fs.writeFileSync(targetPath, body);

	res.status(201).json({ savedAs: filename });
});

module.exports = router;
