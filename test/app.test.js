'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createApp } = require('../src/app');

async function httpGet(baseUrl, path) {
	const res = await fetch(`${baseUrl}${path}`);
	const text = await res.text();
	return { status: res.status, headers: res.headers, text };
}

async function httpPost(baseUrl, path, body) {
	const res = await fetch(`${baseUrl}${path}`, {
		method: 'POST',
		headers: { 'content-type': 'text/plain; charset=utf-8' },
		body,
	});
	const text = await res.text();
	return { status: res.status, headers: res.headers, text };
}

test('GET / returns ok', async () => {
	const app = createApp();	
	const server = app.listen(0);
	const baseUrl = `http://127.0.0.1:${server.address().port}`;

	try {
		const r = await httpGet(baseUrl, '/');
		assert.equal(r.status, 200);
		assert.match(r.text, /"ok"\s*:\s*true/);
	} finally {
		server.close();
	}
});

test('SQL injection style route constructs unsafe query string', async () => {
	const app = createApp();
	const server = app.listen(0);
	const baseUrl = `http://127.0.0.1:${server.address().port}`;

	try {
		const payload = "x' OR '1'='1";
		const r = await httpGet(baseUrl, `/sql?name=${encodeURIComponent(payload)}`);
		assert.equal(r.status, 200);
		assert.match(r.text, /SELECT \* FROM users WHERE name = '/);
		assert.ok(r.text.includes(payload));
	} finally {
		server.close();
	}
});

test('XSS route reflects raw input in HTML', async () => {
	const app = createApp();
	const server = app.listen(0);
	const baseUrl = `http://127.0.0.1:${server.address().port}`;

	try {
		const payload = '<script>alert(1)</script>';
		const r = await httpGet(baseUrl, `/xss?name=${encodeURIComponent(payload)}`);
		assert.equal(r.status, 200);
		assert.ok(r.text.includes(payload));
	} finally {
		server.close();
	}
});

test('Upload route writes file content (insecure upload demo)', async () => {
	const app = createApp();
	const server = app.listen(0);
	const baseUrl = `http://127.0.0.1:${server.address().port}`;

	try {
		const r = await httpPost(baseUrl, '/upload?filename=test.txt', 'hello');
		assert.equal(r.status, 201);
		assert.match(r.text, /test\.txt/);
	} finally {
		server.close();
	}
});
