// Files GitHub issues for the failures found by the Fuzz workflow
// (.github/workflows/fuzz.yml), from the logs its failed jobs upload.
//
// Each finding (a crash, an assertion, a sanitizer report or a malformed reply)
// gets a signature: a hash of the function names of its top stack frames, without
// addresses or offsets, plus the file:line of an assertion. An open issue with the
// fuzzer-crash label and the same "fuzzer-signature:" line gets a comment with the
// new runs; otherwise a new issue is opened. FUZZ_ROUTE_<KIND> ("issue" or "hold")
// says where each kind of finding goes. Nothing is posted unless FUZZ_FILE_ISSUES
// is "true"; the text that would be posted is always written to the output
// directory.
//
// Tests: node .github/scripts/fuzz-report.test.js

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const LABEL = 'fuzzer-crash';
const MARKER = 'fuzzer-signature:';
const TOP_FRAMES = 5;
const MAX_POSTS = 5; // Per run, so that a broken build can't open dozens of issues.
const EXCERPT_LINES = 200;
const EXCERPT_CHARS = 40000; // Issue bodies are limited to 65536 characters.

// Sanitizer reports can be security bugs, which SECURITY.md asks not to report in
// public issues, so they are held back until there is a private route for them.
const DEFAULT_ROUTES = {crash: 'issue', assertion: 'issue', malformed: 'issue', sanitizer: 'hold'};

// Frames of the crash handler, libc, the allocator and the sanitizer runtimes say
// nothing about the bug.
const SKIP_FRAME = new RegExp(
    '^(_serverAssert\\w*|_serverPanic|bugReportStart|bugReportEnd|logStackTrace|sigsegvHandler|' +
    'printCrashReport|removeSigSegvHandlers|__restore_rt|raise|abort|gsignal|pthread_kill|' +
    '__pthread_kill\\w*|__GI_\\w+|__libc_\\w+|_start|start_thread|clone3?|' +
    '_*interceptor_\\w+|__asan_\\w+|__sanitizer_\\w+|__ubsan_\\w+|__lsan_\\w+|' +
    'malloc|calloc|realloc|free|posix_memalign|strdup|' +
    '(z|ztry|valkey_)(malloc|calloc|realloc|free|strdup)\\w*)$');

// Commands whose first argument is a subcommand, for the malformed reply signature.
const CONTAINER_COMMANDS = new Set([
    'ACL', 'CLIENT', 'CLUSTER', 'COMMAND', 'COMMANDLOG', 'CONFIG', 'FUNCTION', 'LATENCY',
    'MEMORY', 'MODULE', 'OBJECT', 'PUBSUB', 'SCRIPT', 'SLOWLOG', 'XGROUP', 'XINFO']);

// The function name in one stack frame line, or null if the frame has none:
//   glibc backtrace_symbols_fd: valkey-server *:6379(call+0x297)[0x567c97]
//                               valkey-server *:6379[0x555e39]   (no symbol)
//   libbacktrace:               #2 0x55d4c4a1b2c3 call at server.c:3912
//   ASan, LSan:                 #2 0x55d4c4a1b2c3 in call /src/server.c:3912:5
// GCC suffixes such as ".isra.0" or ".cold" are removed.
function frameFunction(line) {
    let m = line.match(/^\s*#\d+\s+0x[0-9a-f]+\s+in\s+([^\s(]+)/);
    if (!m) m = line.match(/^\s*#\d+\s+0x[0-9a-f]+\s+([^\s(<][^\s(]*)/);
    if (!m) m = line.match(/\(([^()+\s]+)\+0x[0-9a-f]+\)\s*\[0x[0-9a-f]+\]/);
    return m ? m[1].split('.')[0] : null;
}

// The top function names of a list of frame lines.
function topFunctions(lines) {
    const names = [];
    for (const line of lines) {
        const name = frameFunction(line);
        if (!name || SKIP_FRAME.test(name) || name === names[names.length - 1]) continue;
        names.push(name);
        if (names.length === TOP_FRAMES) break;
    }
    return names;
}

function hash(parts) {
    return crypto.createHash('sha256').update(parts.join('\n')).digest('hex').slice(0, 16);
}

function excerpt(text) {
    const lines = text.split('\n');
    let out = lines.slice(0, EXCERPT_LINES).join('\n');
    if (out.length > EXCERPT_CHARS) out = out.slice(0, EXCERPT_CHARS);
    if (out.length < text.length) out += '\n... (cut, the full log is in the upload)';
    return out;
}

// The first crash report in a server log (debug.c), from "BUG REPORT START" to
// "BUG REPORT END", or to the end of the log if the server died while writing it.
// The INFO, CLIENT LIST, CONFIG DEBUG, MODULES and code dump sections are left out.
function crashReport(log) {
    const start = log.indexOf('BUG REPORT START');
    if (start < 0) return null;
    const end = log.indexOf('BUG REPORT END', start);
    const lines = log.slice(log.lastIndexOf('\n', start) + 1, end < 0 ? log.length : end).split('\n');
    const left = /^------ (INFO OUTPUT|CLIENT LIST OUTPUT|CONFIG DEBUG OUTPUT|MODULES INFO OUTPUT|DUMPING CODE AROUND EIP) ------$/;
    const kept = [];
    let drop = false;
    for (const line of lines) {
        if (/^------ .* ------$/.test(line)) drop = left.test(line);
        if (!drop) kept.push(line);
    }
    return kept.join('\n');
}

// The frames of the thread that crashed or asserted: the EIP frame, if any, then
// the thread marked with " *", or the "Backtrace:" block.
function crashFrames(report) {
    const lines = report.split('\n');
    const frames = [];
    const eip = lines.findIndex((l) => l.trim() === 'EIP:');
    if (eip >= 0 && eip + 1 < lines.length) frames.push(lines[eip + 1]);
    let i = lines.findIndex((l) => /^\d+ \S+ \*$/.test(l) || l.trim() === 'Backtrace:');
    if (i >= 0) {
        for (i++; i < lines.length; i++) {
            if (/^\d+ \S+( \*)?$/.test(lines[i]) || /expected stacktraces|STACK TRACE DONE/.test(lines[i])) break;
            frames.push(lines[i]);
        }
    }
    return frames;
}

function finding(kind, location, functions, summary, report) {
    return {kind, location, functions, summary, report, signature: hash([kind, location, ...functions])};
}

// A finding from a server log with a debug.c crash report, or null.
function crashFinding(log) {
    const report = crashReport(log);
    if (report === null) return null;
    const functions = topFunctions(crashFrames(report));
    let m = report.match(/==> (\S+:\d+) '(.*)' is not true/);
    if (m) return finding('assertion', m[1], functions, `assertion '${m[2]}' failed at ${m[1]}`, report);
    m = report.match(/Guru Meditation: (.*) #(\S+:\d+)/);
    if (m) return finding('assertion', m[2], functions, `panic '${m[1]}' at ${m[2]}`, report);
    m = report.match(/crashed by signal: (\d+)/);
    const what = m ? `signal ${m[1]}` : 'crash';
    return finding('crash', '', functions, `${what} in ${functions[0] || 'an unknown function'}`, report);
}

// Consecutive "#N 0x..." frame lines starting at lines[from].
function frameLines(lines, from) {
    const frames = [];
    for (let i = from; i >= 0 && i < lines.length && /^\s*#\d+ /.test(lines[i]); i++) frames.push(lines[i]);
    return frames;
}

// A finding from a server's stderr with an AddressSanitizer, LeakSanitizer or
// UndefinedBehaviorSanitizer report, or null. Addresses and other numbers are
// left out of the signature.
function sanitizerFinding(stderr) {
    const lines = stderr.split('\n');
    const error = lines.findIndex((l) => /==\d+==ERROR: \w+Sanitizer: /.test(l));
    if (error >= 0) {
        const what = lines[error].replace(/.*ERROR: /, '').split(/ on | at pc | in thread /)[0]
            .replace(/0x[0-9a-f]+|\d+/g, 'N').trim();
        // The first stack after the error line: where a freed block was used, or
        // where a leaked block was allocated.
        const functions = topFunctions(frameLines(lines, lines.findIndex((l, i) => i > error && /^\s*#0 /.test(l))));
        const end = lines.findIndex((l, i) => i > error && /^SUMMARY: /.test(l));
        const report = lines.slice(error, end < 0 ? lines.length : end + 1).join('\n');
        const summary = `${what.replace(':', '')} in ${functions[0] || 'an unknown function'}`;
        return finding('sanitizer', what, functions, summary, report);
    }
    // UBSan: "t_string.c:123:45: runtime error: signed integer overflow: ...". The
    // values in the message change between runs, so the signature only keeps the
    // part before the first colon, with numbers masked.
    const ub = lines.findIndex((l) => / runtime error: /.test(l));
    if (ub >= 0) {
        const m = lines[ub].match(/([^\s/]+:\d+):\d+: runtime error: ([^:]*)/);
        const where = m ? m[1] : 'an unknown place';
        const what = m ? m[2].replace(/\d+/g, 'N').trim() : 'runtime error';
        const report = lines.slice(ub, ub + 40).join('\n');
        return finding('sanitizer', `UBSan ${what} at ${where}`, topFunctions(frameLines(lines, ub + 1)),
                       `UBSan ${what} at ${where}`, report);
    }
    return null;
}

// A finding from the fuzzer's output when it got a malformed reply, or null. The
// signature is the command and, for a container command, its subcommand.
function malformedFinding(output) {
    const m = output.match(/Command that caused malformed reply: ([^\r\n]*)/);
    if (!m) return null;
    const words = m[1].trim().split(/\s+/);
    let command = /^[A-Za-z][\w-]*$/.test(words[0] || '') ? words[0].toUpperCase() : 'an unknown command';
    if (CONTAINER_COMMANDS.has(command) && /^[A-Za-z][A-Za-z-]*$/.test(words[1] || '')) {
        command += ' ' + words[1].toUpperCase();
    }
    const at = output.indexOf('MALFORMED REPLY DETECTED');
    const start = output.lastIndexOf('\n', at) + 1;
    const end = output.indexOf('ABORTING ALL THREADS', at);
    const report = output.slice(start, end < 0 ? output.length : end).replace(/\r/g, '\n');
    return finding('malformed', command, [], `malformed reply to ${command}`, report);
}

// The text of a file from a little before the first marker, up to maxBytes, or ''
// if the marker isn't there. Server logs of long runs can be larger than a string
// can hold, so the file is searched in chunks.
function readFrom(file, marker, maxBytes = 4 << 20) {
    if (!fs.existsSync(file)) return '';
    const fd = fs.openSync(file, 'r');
    try {
        const size = fs.fstatSync(fd).size;
        const chunk = Buffer.alloc(Math.min(size, 16 << 20) + marker.length);
        for (let pos = 0; pos < size; pos += chunk.length - marker.length) {
            const n = fs.readSync(fd, chunk, 0, chunk.length, pos);
            const i = chunk.subarray(0, n).indexOf(marker);
            if (i < 0) continue;
            const start = Math.max(0, pos + i - 4096);
            const out = Buffer.alloc(Math.min(maxBytes, size - start));
            fs.readSync(fd, out, 0, out.length, start);
            return out.toString('latin1');
        }
        return '';
    } finally {
        fs.closeSync(fd);
    }
}

// key: value lines of fuzz-info.txt.
function readInfo(file) {
    const info = {};
    if (!fs.existsSync(file)) return info;
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
        const m = line.match(/^(\w+): (.*)$/);
        if (m) info[m[1]] = m[2].trim();
    }
    return info;
}

// The findings in one failed job's upload: fuzz-info.txt, tests/tmp/server.*/
// (stdout, stderr) and tests/tmp/fuzz-soak.*/output.txt. A server with a
// sanitizer report counts once, as a sanitizer finding.
function findingsInUpload(dir) {
    const info = readInfo(path.join(dir, 'fuzz-info.txt'));
    const tmp = path.join(dir, 'tests', 'tmp');
    const entries = fs.existsSync(tmp) ? fs.readdirSync(tmp).sort() : [];
    const found = [];
    for (const entry of entries) {
        const sub = path.join(tmp, entry);
        let f = null;
        if (entry.startsWith('server.')) {
            const stderr = path.join(sub, 'stderr');
            f = sanitizerFinding(readFrom(stderr, 'Sanitizer') || readFrom(stderr, 'runtime error')) ||
                crashFinding(readFrom(path.join(sub, 'stdout'), 'BUG REPORT START'));
        } else if (entry.startsWith('fuzz-soak.')) {
            f = malformedFinding(readFrom(path.join(sub, 'output.txt'), 'MALFORMED REPLY DETECTED'));
        }
        if (f) found.push(f);
    }
    return {info, found};
}

function cellOf(info) {
    const cell = {};
    for (const kv of (info.cell || '').split(' ')) {
        const [k, v] = kv.split('=');
        if (v) cell[k] = v;
    }
    return cell;
}

function runsTable(runs) {
    const rows = runs.map(({info}) => {
        const c = cellOf(info);
        const run = info.run ? `[${info.run.split('/').pop()}](${info.run})` : 'unknown';
        return `| ${run} | ${c.setup}, ${c.mode}, ${c.build} | ${info.seed || 'unknown'} | ${(info.commit || '').slice(0, 10)} |`;
    });
    return ['| Run | Setup, mode, build | Seed | Commit |', '|---|---|---|---|', ...rows].join('\n');
}

function replay({info}) {
    const c = cellOf(info);
    const seed = info.seed || '<seed>';
    const duration = info.duration || '<duration>';
    return [
        `To replay the first run locally, build with \`${info.make || 'make'}\`, then run:`,
        '```',
        `./runtest --single unit/fuzz-soak --fuzz-soak --fuzz-setup ${c.setup} --fuzz-mode ${c.mode} --fuzz-duration ${duration} --fuzz-seed ${seed}`,
        '```',
        `Or run the Fuzz workflow with setup \`${c.setup}\`, mode \`${c.mode}\`, build \`${c.build}\`, duration \`${duration}\` and seed \`${seed}\`.`,
        'With the seed, each client sends the same commands again, but not in the same order relative to the other clients, so a timing bug may need several reruns.',
    ].join('\n');
}

function signatureText(f) {
    const frames = f.functions.length ? '```\n' + f.functions.join('\n') + '\n```' : '';
    if (f.kind === 'malformed') return `The signature is the command, \`${f.location}\`.`;
    if (f.kind === 'crash') return `The signature is the top stack frames:\n${frames}`;
    return `The signature is \`${f.location}\` and the top stack frames:\n${frames}`;
}

function issueTitle(f) {
    return `${f.kind === 'malformed' ? '[BUG]' : '[CRASH]'} Fuzzer: ${f.summary}`.slice(0, 200);
}

function issueBody(f, runs) {
    return [
        `The scheduled fuzzer (.github/workflows/fuzz.yml) found this ${f.kind === 'malformed' ? 'malformed reply' : f.kind}.`,
        '',
        `${MARKER} ${f.signature}`,
        '',
        runsTable(runs),
        '',
        signatureText(f),
        '',
        replay(runs[0]),
        '',
        '<details><summary>Report</summary>',
        '',
        '```',
        excerpt(f.report).replace(/```/g, "'''"),
        '```',
        '</details>',
        '',
        'The full server logs are in the upload of each run.',
    ].join('\n');
}

function commentBody(f, runs) {
    return [`Seen again (${MARKER} ${f.signature}):`, '', runsTable(runs), '', replay(runs[0])].join('\n');
}

// The oldest open issue (not a pull request) whose body has the signature's
// marker line, or null.
function findIssue(issues, signature) {
    const line = new RegExp(`^${MARKER} ${signature}\\s*$`, 'm');
    const matches = issues.filter((i) => !i.pull_request && line.test(i.body || ''));
    matches.sort((a, b) => a.number - b.number);
    return matches[0] || null;
}

// "issue" or "hold" for a kind of finding. Anything but "issue" holds it back.
function routeFor(kind, env) {
    return (env[`FUZZ_ROUTE_${kind.toUpperCase()}`] || DEFAULT_ROUTES[kind]) === 'issue' ? 'issue' : 'hold';
}

async function ensureLabel(github, owner, repo) {
    try {
        await github.rest.issues.getLabel({owner, repo, name: LABEL});
    } catch (e) {
        if (e.status !== 404) throw e;
        await github.rest.issues.createLabel({owner, repo, name: LABEL, color: 'b60205', description: 'Found by the scheduled fuzzer'});
    }
}

// Reads the uploads in inputDir (one directory per failed job), writes what would
// be posted to outputDir, and posts it when env.FUZZ_FILE_ISSUES is "true".
async function run({github, context, core, inputDir, outputDir, env = process.env}) {
    const post = env.FUZZ_FILE_ISSUES === 'true';
    const {owner, repo} = context.repo;
    fs.mkdirSync(outputDir, {recursive: true});

    // The findings of every failed job, grouped by signature.
    const groups = new Map();
    const unexplained = [];
    const uploads = fs.existsSync(inputDir) ? fs.readdirSync(inputDir).sort() : [];
    for (const upload of uploads) {
        const {info, found} = findingsInUpload(path.join(inputDir, upload));
        if (found.length === 0) unexplained.push(upload);
        for (const f of found) {
            if (!groups.has(f.signature)) groups.set(f.signature, {finding: f, runs: []});
            const runs = groups.get(f.signature).runs;
            if (!runs.some((r) => r.upload === upload)) runs.push({upload, info});
        }
    }

    const summary = [`# Fuzz findings (${post ? 'posting' : 'dry run'})`, ''];
    let issues = [];
    if (groups.size) {
        try {
            issues = await github.paginate(github.rest.issues.listForRepo, {owner, repo, state: 'open', labels: LABEL, per_page: 100});
        } catch (e) {
            // For example, issues are turned off in a fork.
            if (post) throw e;
            summary.push(`Could not list issues (${e.message}), so every finding shows as new.`, '');
        }
    }

    const held = [];
    let posts = 0;
    for (const [signature, {finding: f, runs}] of groups) {
        const where = `${f.kind} ${signature} (${f.summary}) in ${runs.map((r) => r.upload).join(', ')}`;
        if (routeFor(f.kind, env) === 'hold') {
            held.push(f.kind);
            summary.push(`- ${where}: held back, not filed`);
            continue;
        }
        const existing = findIssue(issues, signature);
        const action = existing ? `comment on #${existing.number}` : 'open a new issue';
        const text = existing ? commentBody(f, runs) : `# ${issueTitle(f)}\n\n${issueBody(f, runs)}`;
        fs.writeFileSync(path.join(outputDir, `${signature}.md`), `<!-- would ${action} -->\n${text}\n`);
        if (!post) {
            summary.push(`- ${where}: would ${action}`);
        } else if (posts >= MAX_POSTS) {
            summary.push(`- ${where}: not posted, more than ${MAX_POSTS} findings in this run`);
        } else {
            posts++;
            if (existing) {
                await github.rest.issues.createComment({owner, repo, issue_number: existing.number, body: commentBody(f, runs)});
            } else {
                await ensureLabel(github, owner, repo);
                await github.rest.issues.create({owner, repo, title: issueTitle(f), body: issueBody(f, runs), labels: [LABEL]});
            }
            summary.push(`- ${where}: did ${action}`);
        }
    }
    for (const upload of unexplained) {
        summary.push(`- ${upload}: no crash report, sanitizer report or malformed reply found, see the job log`);
    }
    if (uploads.length === 0) summary.push('No failed job uploaded logs.');

    const text = summary.join('\n') + '\n';
    fs.writeFileSync(path.join(outputDir, 'summary.md'), text);
    if (core) {
        await core.summary.addRaw(text).write();
        // TODO: send held-back findings to a private alert once the maintainers agree on one.
        if (held.length) core.setFailed(`Held back ${held.length} finding(s): ${[...new Set(held)].join(', ')}. See the summary.`);
    }
    return {groups, held, unexplained, summary: text};
}

module.exports = {
    frameFunction, topFunctions, crashReport, crashFinding, sanitizerFinding, malformedFinding,
    readFrom, findingsInUpload, findIssue, routeFor, issueTitle, issueBody, commentBody, run, LABEL, MARKER,
};
