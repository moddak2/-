'use strict';

const { createApp } = require('./app');

function parsePort(argv) {
	const args = argv.slice(2);
	for (let i = 0; i < args.length; i += 1) {
		if (args[i] === '--port') {
			const next = args[i + 1];
			if (!next) throw new Error('Missing value for --port');
			const port = Number(next);
			if (!Number.isInteger(port) || port <= 0) throw new Error('Invalid --port value');
			return port;
		}
	}
	return 3000;
}

function main() {
	const port = parsePort(process.argv);
	const app = createApp();
	app.listen(port, () => {
		process.stdout.write(`listening on http://127.0.0.1:${port}\n`);
	});
}

if (require.main === module) {
	main();
}

module.exports = { main };
