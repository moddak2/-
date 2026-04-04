'use strict';

// INTENTIONALLY VULNERABLE DEMO FILE (EXTRA)
// 목적: 6개 기본 카테고리 외에 1~2개 더 탐지되도록 추가 샘플 제공.
// 주의: 앱 실행 경로(라우팅/require)에 연결하지 마세요.

const crypto = require('node:crypto');

function demoOpenRedirect(req, res) {
	// Open Redirect: user-controlled URL used as redirect target
	res.redirect(String(req.query.next ?? '/'));
}

function demoWeakCryptoMd5(req, res) {
	// Weak crypto: MD5 used for hashing user input
	const digest = crypto
		.createHash('md5')
		.update(String(req.body ?? req.query.password ?? ''), 'utf8')
		.digest('hex');
	res.status(200).type('text').send(digest);
}

module.exports = {
	demoOpenRedirect,
	demoWeakCryptoMd5,
};
