'use strict';

// Simple "build" step for a JS-only project:
// - Ensures key modules can be loaded without syntax/runtime errors on import.
// - Does NOT start the HTTP server.

require('../src/app');
require('../src/routes/index');
require('../src/routes/upload');

process.stdout.write('build ok\n');
