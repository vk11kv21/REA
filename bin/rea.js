#!/usr/bin/env node
import { run } from "../src/cli.js";
import { UsageError } from "../src/lib/util.js";

run(process.argv.slice(2)).catch(error => {
  if (error instanceof UsageError) {
    process.stderr.write(`error: ${error.message}\n`);
    process.exit(error.exitCode ?? 2);
  }
  process.stderr.write(`${error?.stack || error}\n`);
  process.exit(1);
});
