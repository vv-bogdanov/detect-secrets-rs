#!/usr/bin/env node
"use strict";

const { runBinary } = require("../lib/run-binary");

runBinary("detect-secrets-rs", process.argv.slice(2));
