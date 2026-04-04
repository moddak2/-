'use strict';

const fs = require('node:fs');
const path = require('node:path');

function listFilesRecursive(dir) {
	const out = [];
	for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
		const p = path.join(dir, entry.name);
		if (entry.isDirectory()) out.push(...listFilesRecursive(p));
		else out.push(p);
	}
	return out;
}

function toPos(text, index) {
	// 1-based line/col
	let line = 1;
	let lastNewline = -1;
	for (let i = 0; i < index; i += 1) {
		if (text.charCodeAt(i) === 10) {
			line += 1;
			lastNewline = i;
		}
	}
	return { line, col: index - lastNewline };
}

function findAll(text, regex) {
	const matches = [];
	const r = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : `${regex.flags}g`);
	let m;
	while ((m = r.exec(text)) !== null) {
		matches.push({ index: m.index, match: m[0] });
		if (m.index === r.lastIndex) r.lastIndex += 1;
	}
	return matches;
}

function scanFile(filePath, relPath, text) {
	const findings = [];

	// Heuristic patterns intentionally tuned to this demo code.
	const rules = [
		{
			id: 'SQL_INJECTION_STRING_CONCAT',
			severity: 'high',
			description: 'Unsafe SQL query construction via string interpolation/concatenation.',
			regex: /SELECT\s+\*\s+FROM[\s\S]{0,200}WHERE[\s\S]{0,200}\$\{[\s\S]{0,200}\}/i,
		},
		{
			id: 'REFLECTED_XSS_UNESCAPED',
			severity: 'high',
			description: 'Unescaped user input reflected into HTML response.',
			regex: /type\(['"]html['"]\)[\s\S]{0,200}send\([\s\S]{0,400}\$\{[\s\S]{0,200}\}\)/i,
		},
		{
			id: 'DIR_TRAVERSAL_PATH_JOIN',
			severity: 'high',
			description: 'Path built from user input without validation/allowlist, then read from disk.',
			regex: /const\s+userPath\s*=\s*String\(req\.query\.[^)]*\)[\s\S]{0,300}path\.join\([^\)]*userPath[^\)]*\)[\s\S]{0,300}readFileSync\(/i,
		},
		{
			id: 'INSECURE_FILE_UPLOAD',
			severity: 'high',
			description: 'File upload writes user-supplied filename/content without validation.',
			regex: /const\s+filename\s*=\s*String\(req\.query\.filename[\s\S]{0,400}writeFileSync\(/i,
		},
	];

	for (const rule of rules) {
		for (const hit of findAll(text, rule.regex)) {
			const pos = toPos(text, hit.index);
			findings.push({
				ruleId: rule.id,
				severity: rule.severity,
				file: relPath,
				line: pos.line,
				col: pos.col,
				description: rule.description,
			});
		}
	}

	// Avoid suggesting secrets: we intentionally do NOT scan/seed hardcoded secrets here.

	return findings;
}

function main() {
	const root = process.cwd();
	const srcDir = path.join(root, 'src');
	if (!fs.existsSync(srcDir)) {
		process.stderr.write('No src/ directory found.\n');
		process.exitCode = 2;
		return;
	}

	const files = listFilesRecursive(srcDir).filter((p) => p.endsWith('.js'));
	let all = [];
	for (const f of files) {
		const rel = path.relative(root, f).split(path.sep).join('/');
		const text = fs.readFileSync(f, 'utf8');
		all = all.concat(scanFile(f, rel, text));
	}

	all.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId));

	process.stdout.write(`Findings: ${all.length}\n`);
	for (const f of all) {
		process.stdout.write(`- [${f.severity}] ${f.ruleId} ${f.file}:${f.line}:${f.col} — ${f.description}\n`);
	}

	// Non-zero exit if any high findings.
	if (all.some((x) => x.severity === 'high')) process.exitCode = 1;
}

main();
