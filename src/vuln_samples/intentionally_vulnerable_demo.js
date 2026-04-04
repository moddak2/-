'use strict';

// INTENTIONALLY VULNERABLE DEMO FILE
// 목적: semgrep/gitleaks/로컬 스캐너가 취약점을 "탐지"하도록 하는 샘플 코드.
// 주의: 이 파일은 앱 실행 경로(라우팅/require)에 연결하지 마세요.

const { exec } = require('node:child_process');

// Hardcoded secrets (FAKE / DEMO VALUES)
// NOTE: 일부 플랫폼(GitHub 등)에서 특정 토큰 패턴은 푸시를 차단할 수 있어,
//       여기서는 "generic secret/password/token" 형태로만 시딩합니다.
// NOTE: GitHub Push Protection에 걸릴 수 있는 유명 벤더 키 패턴(AWS 등)은 피합니다.
// 대신 "generic token" 형태(고엔트로피 + 키워드)를 사용해 gitleaks/semgrep 데모 탐지를 유도합니다.
const API_TOKEN = 'demo_token_6b9c7f1f0a2d4c2bb0e8d0c8d8f2a1c4c7e9b0f1a2d3c4b5';
const JWT_SECRET = 'demo_jwt_secret_9c2b5e8a7f1d3c4b6a8e0d2c4b6a8e0d2c4b6a8e0';

function demoCommandInjection(req, res) {
	// Command Injection: user input directly reaches OS command execution
	exec(String(req.query.cmd ?? 'echo hello'), { windowsHide: true }, (err, stdout, stderr) => {
		res
			.status(200)
			.type('text')
			.send(String(stdout || stderr || (err && err.message) || ''));
	});
}

function demoInsecureDeserialization(req, res) {
	// Insecure Deserialization: node-serialize unserialize on untrusted input
	// NOTE: dependency is intentionally not installed; this file is a scan-only fixture.
	// eslint-disable-next-line global-require
	const serialize = require('node-serialize');
	const obj = serialize.unserialize(String(req.body ?? req.query.data ?? ''));
	res.status(200).json({ ok: true, obj });
}

module.exports = {
	demoCommandInjection,
	demoInsecureDeserialization,
	API_TOKEN,
	JWT_SECRET,
};
