'use strict';

// INTENTIONALLY VULNERABLE DEMO FILE (MORE)
// 목적: 사진의 6개 항목(SQLi, XSS, Path Traversal, Command Injection, Hardcoded Secret, Insecure Deserialization)
//       이 모두가 "골고루" 포함되면서, 전체 탐지 건수를 20개 수준까지 늘리기 위한 스캔 전용 샘플.
// 주의: 앱 실행 경로(라우팅/require)에 연결하지 마세요.

const fs = require('node:fs');
const path = require('node:path');
const { exec, execSync } = require('node:child_process');

// Hardcoded secrets (demo)
const password_demo_1 = 'demo_password_aaaaaaaaaaaaaaaaaaaa';
const api_token_demo_2 = 'demo_token_bbbbbbbbbbbbbbbbbbbb';
const secret_key_demo_3 = 'demo_secret_cccccccccccccccccccc';

function demoSqlInjection1(req, res) {
	// SQL Injection style unsafe query construction (concat)
	const name = String(req.query.name ?? '');
	const q = "SELECT * FROM users WHERE name = '" + name + "'";
	res.status(200).type('text').send(q);
}

function demoSqlInjection2(req, res) {
	// SQL Injection style unsafe query construction (template)
	const id = String(req.query.id ?? '');
	const q = `SELECT * FROM accounts WHERE id = ${id}`;
	res.status(200).type('text').send(q);
}

function demoXss(req, res) {
	// Reflected XSS (no escaping)
	res
		.status(200)
		.type('html')
		.send(`<h1>${String(req.query.q ?? '')}</h1>`);
}

function demoPathTraversal(req, res) {
	// Path Traversal: user-controlled path used with path.join + readFileSync
	const baseDir = path.join(process.cwd(), 'public', 'uploads');
	const userPath = String(req.query.file ?? '');
	const targetPath = path.join(baseDir, userPath);
	const data = fs.readFileSync(targetPath);
	res.status(200).type('application/octet-stream').send(data);
}

function demoCommandInjection1(req, res) {
	// Command Injection: user input reaches exec()
	exec(String(req.query.cmd ?? 'echo hi'), { windowsHide: true }, (err, stdout, stderr) => {
		res.status(200).type('text').send(String(stdout || stderr || (err && err.message) || ''));
	});
}

function demoCommandInjection2(req, res) {
	// Command Injection: user input reaches execSync()
	const out = execSync(String(req.body.cmd ?? 'echo hi'), { windowsHide: true });
	res.status(200).type('text').send(String(out));
}

function demoInsecureDeserialization1(req, res) {
	// Insecure Deserialization: unserialize untrusted input
	// eslint-disable-next-line global-require
	const serialize = require('node-serialize');
	const obj = serialize.unserialize(String(req.query.data ?? ''));
	res.status(200).json({ ok: true, obj });
}

function demoInsecureDeserialization2(req, res) {
	// Insecure Deserialization: unserialize untrusted input
	// eslint-disable-next-line global-require
	const serialize = require('node-serialize');
	const obj = serialize.unserialize(String(req.body.payload ?? ''));
	res.status(200).json({ ok: true, obj });
}

module.exports = {
	demoSqlInjection1,
	demoSqlInjection2,
	demoXss,
	demoPathTraversal,
	demoCommandInjection1,
	demoCommandInjection2,
	demoInsecureDeserialization1,
	demoInsecureDeserialization2,
	password_demo_1,
	api_token_demo_2,
};
