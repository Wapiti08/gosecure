#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

function usage() {
    // use global variable
    process.stderr.write(
        "usage: node resolve.js <project-root> [--no-dev]\n"
    );
}

function readJSON(filepath) {
    return JSON.parse(fs.readFileSync(filepath, "utf8"));
}

// extract package name from specific key (normally it is a path instead of package names)
function packageNameFromLockKey(key) {
    const marker = "node_modules/";
    // from last to begin to find last apperance location
    const idx = key.lastIndexOf(marker);
    // strict equality operator
    if (idx=== -1) return null;
    return key.slice(idx + marker.length);
}

// parse npm lock file
function parseNpmLock(root, includeDev) {
    // use file including exactly installed dependencies
    const lockPath = path.join(root, "package-lock.json" );
    if (!fs.existsSync(lockPath)) {
        throw new Error("package-lock.json not found");
    }

    const lock = readJSON(lockPath);
    const pkgPath = path.join(root, "package.json");
    // ? - if, : -> else
    const pkg = fs.existsSync(pkgPath) ? readJSON(pkgPath) : {};
    // Object.keys -> extract all keys; new Set(): covert array to Set
    const rootDeps = new Set(Object.keys(pkg.dependencies || {}));
    const rootDevDeps = new Set(Object.keys(pkg.devDependencies || {}));

    // save dependencies that have been processed
    const seen = new Map(); // name@version -> dep

    // in lock file, the key name is "packages"
    for (const [key, entry] of Object.entries(lock.packages || {})) {
        if (key==="" || !entry || !entry.version) continue;

        const name = packageNameFromLockKey(key);
        if (!name) continue;

        const isDirect = rootDeps.has(name) || rootDevDeps.has(name);
        const isDev = rootDevDeps.has(name) && !rootDeps.has(name);
        
        // check whether include dev
        if (!includeDev && isDev) continue;

        // define saved format for value in defined map
        const dep = {
            name,
            version: entry.version,
            direct: isDirect,
            dev: isDev,
          };

        
        const dedupeKey = `${name}@${entry.version}`;
        seen.set(dedupeKey, dep);
    }

    return {
        
    }


}