// Tests for fuzz-report.js. Run with: node .github/scripts/fuzz-report.test.js
//
// The logs in fuzz-report-testdata/ are real, trimmed to the crash report, with
// local paths replaced:
// - *-canary-*: a fuzz-soak run against a build with a deliberate assertion in
//   STRLEN (t_string.c:1155), so every server of a run hit the same bug. glibc-*
//   are from a build without libbacktrace, libbacktrace-* from builds with it
//   (node1 and node2: ASan, normal: no sanitizer).
// - *-debug: DEBUG ASSERT and DEBUG SEGFAULT.
// - glibc-assert-5422.stdout: the crash report posted in #5422.
// - glibc-watchdog.stdout: a watchdog stack trace, which is not a crash.
// - asan-*.stderr: a leak and a use after free in STRLEN under ASan.
// - ubsan-overflow.stderr: UBSan output for a signed overflow.
// - fuzzer-malformed-function-list.txt: valkey-benchmark output for the FUNCTION
//   LIST malformed reply.

'use strict';

const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {test} = require('node:test');
const r = require('./fuzz-report.js');

const data = (name) => fs.readFileSync(path.join(__dirname, 'fuzz-report-testdata', name), 'latin1');
const crash = (name) => r.crashFinding(data(name));

test('frame lines in each format', () => {
    assert.equal(r.frameFunction('/src/valkey-server 127.0.0.1:25000(call+0x297)[0x567c97]'), 'call');
    assert.equal(r.frameFunction('/src/valkey-server 127.0.0.1:25000[0x555e39]'), null);
    assert.equal(r.frameFunction('/lib64/libpthread.so.0(+0x744b)[0x7f51a98a044b]'), null);
    assert.equal(r.frameFunction('#1 0x5a0a8f debugCommand at /src/debug.c:569'), 'debugCommand');
    assert.equal(r.frameFunction('#0 0x7f4ca99df8df <unknown>'), null);
    assert.equal(r.frameFunction('    #4 0x8b0aa4 in strlenCommand /src/t_string.c:1155'), 'strlenCommand');
    assert.equal(r.frameFunction('    #17 0x7f0b47f09139 in __libc_start_main (/lib64/libc.so.6+0x21139)'), '__libc_start_main');
    assert.equal(r.frameFunction('    #20 0x46e289  (/src/valkey-server+0x46e289)'), null);
    assert.equal(r.frameFunction('#3 0x4f8b5a lookupKey.isra.0 at db.c:12'), 'lookupKey');
});

test('the same bug gets the same signature', () => {
    // On different servers of a cluster and on a standalone server.
    assert.equal(crash('glibc-assert-canary-standalone.stdout').signature, crash('glibc-assert-canary-cluster-node.stdout').signature);
    // With libbacktrace, in an ASan build and a normal build.
    const node1 = crash('libbacktrace-assert-canary-node1.stdout');
    assert.equal(node1.signature, crash('libbacktrace-assert-canary-node2.stdout').signature);
    assert.equal(node1.signature, crash('libbacktrace-assert-canary-normal.stdout').signature);
    assert.deepEqual(node1.functions, ['strlenCommand', 'call', 'processCommand', 'processCommandAndResetClient', 'processInputBuffer']);
    // With and without libbacktrace, when no frame is a static function.
    assert.equal(crash('glibc-assert-debug.stdout').signature, crash('libbacktrace-assert-debug.stdout').signature);
    assert.equal(crash('glibc-segfault-debug.stdout').signature, crash('libbacktrace-segfault-debug.stdout').signature);
});

test('addresses and offsets are not part of the signature', () => {
    const log = data('glibc-assert-canary-standalone.stdout');
    const moved = log.replace(/0x[0-9a-f]+/g, (h) => '0x' + (parseInt(h, 16) + 0x1230).toString(16));
    assert.notEqual(moved, log);
    assert.equal(r.crashFinding(moved).signature, r.crashFinding(log).signature);
});

test('different bugs get different signatures', () => {
    const signatures = [
        'glibc-assert-canary-standalone.stdout', 'glibc-assert-debug.stdout', 'glibc-segfault-debug.stdout', 'glibc-assert-5422.stdout',
    ].map((name) => crash(name).signature);
    signatures.push(r.sanitizerFinding(data('asan-leak-canary.stderr')).signature);
    signatures.push(r.sanitizerFinding(data('asan-uaf-canary.stderr')).signature);
    assert.equal(new Set(signatures).size, signatures.length);
});

test('assertions, crashes and panics', () => {
    const a = crash('glibc-assert-5422.stdout');
    assert.equal(a.kind, 'assertion');
    assert.equal(a.location, 'server.c:1160');
    // The static functions (updateClientMemUsageAndBucket and one other) have no name.
    assert.deepEqual(a.functions, ['beforeNextClient', 'readQueryFromClient', 'aeMain', 'main']);
    assert.equal(r.issueTitle(a), "[CRASH] Fuzzer: assertion 'c->conn' failed at server.c:1160");

    const s = crash('libbacktrace-segfault-debug.stdout');
    assert.equal(s.kind, 'crash');
    assert.equal(s.summary, 'signal 11 in debugCommand');
    assert.doesNotMatch(s.report, /INFO OUTPUT\n# Server/);

    const panic = r.crashFinding('=== VALKEY BUG REPORT START: Cut & paste starting from here ===\n' +
                                 '1:M 01 Jan 2026 00:00:00.000 # Guru Meditation: Unknown encoding type #t_hash.c:42\n');
    assert.equal(panic.kind, 'assertion');
    assert.equal(panic.location, 't_hash.c:42');

    assert.equal(crash('glibc-watchdog.stdout'), null);
    assert.equal(r.crashFinding('just a log\n'), null);
});

test('sanitizer reports', () => {
    const uaf = r.sanitizerFinding(data('asan-uaf-canary.stderr'));
    assert.equal(uaf.location, 'AddressSanitizer: heap-use-after-free');
    assert.equal(uaf.functions[0], 'strlenCommand');
    const leak = r.sanitizerFinding(data('asan-leak-canary.stderr'));
    assert.equal(leak.location, 'LeakSanitizer: detected memory leaks');
    // The allocator frames (malloc, ztrymalloc_usable_internal, valkey_malloc, zstrdup) are skipped.
    assert.equal(leak.functions[0], 'strlenCommand');
    const ub = r.sanitizerFinding(data('ubsan-overflow.stderr'));
    assert.equal(ub.location, 'UBSan signed integer overflow at t_overflow.c:4');
    assert.equal(r.sanitizerFinding(''), null);
});

test('malformed reply', () => {
    const m = r.malformedFinding(data('fuzzer-malformed-function-list.txt'));
    assert.equal(m.kind, 'malformed');
    assert.equal(m.location, 'FUNCTION LIST');
    assert.equal(r.issueTitle(m), '[BUG] Fuzzer: malformed reply to FUNCTION LIST');
    assert.equal(r.malformedFinding('Fuzz outcome: clean (exit code 0)\n'), null);
});

test('a marker that spans two read chunks is found in a large log', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuzz-report-'));
    const file = path.join(dir, 'stdout');
    const report = data('glibc-assert-debug.stdout');
    const at = report.indexOf('BUG REPORT START');
    fs.writeFileSync(file, Buffer.concat([Buffer.alloc((16 << 20) - at - 5, 'x'), Buffer.from(report, 'latin1')]));
    assert.equal(r.crashFinding(r.readFrom(file, 'BUG REPORT START')).signature, crash('glibc-assert-debug.stdout').signature);
    fs.rmSync(dir, {recursive: true});
});

test('matching an open issue', () => {
    const sig = crash('glibc-assert-debug.stdout').signature;
    const issues = [
        {number: 7, body: `fuzzer-signature: ${sig}`, pull_request: {}},
        {number: 9, body: `text\nfuzzer-signature: ${sig}\nmore`},
        {number: 8, body: `fuzzer-signature: ${sig}`},
        {number: 6, body: `see fuzzer-signature: ${sig} in #8`},
    ];
    assert.equal(r.findIssue(issues, sig).number, 8);
    assert.equal(r.findIssue(issues, '0123456789abcdef'), null);
});

test('routes', () => {
    assert.equal(r.routeFor('sanitizer', {}), 'hold');
    assert.equal(r.routeFor('crash', {}), 'issue');
    assert.equal(r.routeFor('sanitizer', {FUZZ_ROUTE_SANITIZER: 'issue'}), 'issue');
    assert.equal(r.routeFor('crash', {FUZZ_ROUTE_CRASH: 'hold'}), 'hold');
    assert.equal(r.routeFor('crash', {FUZZ_ROUTE_CRASH: 'yes'}), 'hold');
});

// Uploads as download-artifact writes them: one directory per failed job.
function makeUploads() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuzz-report-'));
    const upload = (name, info, files) => {
        fs.mkdirSync(path.join(dir, 'in', name), {recursive: true});
        fs.writeFileSync(path.join(dir, 'in', name, 'fuzz-info.txt'), info + '\n');
        for (const [file, text] of Object.entries(files)) {
            const p = path.join(dir, 'in', name, 'tests', 'tmp', file);
            fs.mkdirSync(path.dirname(p), {recursive: true});
            fs.writeFileSync(p, text);
        }
    };
    const info = (setup, mode, build, seed) => [
        `cell: setup=${setup} mode=${mode} build=${build}`, 'commit: 0123456789abcdef',
        'run: https://github.com/o/r/actions/runs/1234', `make: make ${build}`, 'duration: 1800', `seed: ${seed}`].join('\n');
    upload('fuzz-logs-cluster-default-asan', info('cluster', 'default', 'asan', 111), {
        'server.1.1/stdout': data('libbacktrace-assert-canary-node1.stdout'), 'server.1.1/stderr': '',
        'server.1.3/stdout': data('libbacktrace-assert-canary-node2.stdout'), 'server.1.3/stderr': '',
        'fuzz-soak.1.7/output.txt': 'Fuzz outcome: server unreachable (exit code 3)\n'});
    upload('fuzz-logs-standalone-default-normal', info('standalone', 'default', 'normal', 222), {
        'server.2.1/stdout': data('libbacktrace-assert-canary-normal.stdout')});
    upload('fuzz-logs-standalone-default-ubsan', info('standalone', 'default', 'ubsan', 333), {
        'server.3.1/stdout': 'log\n', 'server.3.1/stderr': data('ubsan-overflow.stderr')});
    upload('fuzz-logs-standalone-malformed-commands-normal', info('standalone', 'malformed-commands', 'normal', 444), {
        'server.4.1/stdout': 'log\n', 'fuzz-soak.4.3/output.txt': data('fuzzer-malformed-function-list.txt')});
    upload('fuzz-logs-standalone-config-commands-normal', info('standalone', 'config-commands', 'normal', 555), {
        'server.5.1/stdout': 'log\n', 'fuzz-soak.5.3/output.txt': 'Fuzz outcome: server unreachable (exit code 3)\n'});
    return dir;
}

function fakeGitHub(issues, {listFails = false} = {}) {
    const calls = [];
    const rest = {issues: {
        listForRepo: 'listForRepo',
        createComment: async (args) => calls.push(['createComment', args]),
        create: async (args) => calls.push(['create', args]),
        getLabel: async () => {
            throw Object.assign(new Error('Not Found'), {status: 404});
        },
        createLabel: async (args) => calls.push(['createLabel', args]),
    }};
    const paginate = async (method, args) => {
        calls.push(['list', args]);
        if (listFails) throw new Error('Issues are disabled for this repo');
        return issues;
    };
    return {github: {rest, paginate}, calls};
}

function fakeCore() {
    const core = {failed: null, text: ''};
    core.setFailed = (msg) => (core.failed = msg);
    core.summary = {addRaw: (t) => ((core.text += t), core.summary), write: async () => {}};
    return core;
}

const context = {repo: {owner: 'o', repo: 'r'}};
const canary = () => crash('libbacktrace-assert-canary-node1.stdout').signature;

test('dry run writes what it would post and posts nothing', async () => {
    const dir = makeUploads();
    const {github, calls} = fakeGitHub([{number: 42, body: `fuzzer-signature: ${canary()}`}]);
    const core = fakeCore();
    const out = path.join(dir, 'out');
    const result = await r.run({github, context, core, inputDir: path.join(dir, 'in'), outputDir: out, env: {}});

    assert.deepEqual(calls.map((c) => c[0]), ['list']);
    assert.equal(calls[0][1].labels, 'fuzzer-crash');
    assert.equal(result.groups.size, 3);
    const comment = fs.readFileSync(path.join(out, `${canary()}.md`), 'utf8');
    assert.match(comment, /would comment on #42/);
    assert.match(comment, /\| cluster, default, asan \| 111 \|/);
    assert.match(comment, /\| standalone, default, normal \| 222 \|/);
    const malformed = r.malformedFinding(data('fuzzer-malformed-function-list.txt')).signature;
    const issue = fs.readFileSync(path.join(out, `${malformed}.md`), 'utf8');
    assert.match(issue, /would open a new issue/);
    assert.match(issue, new RegExp(`^fuzzer-signature: ${malformed}$`, 'm'));
    assert.match(issue, /--fuzz-setup standalone --fuzz-mode malformed-commands --fuzz-duration 1800 --fuzz-seed 444/);
    const summary = fs.readFileSync(path.join(out, 'summary.md'), 'utf8');
    assert.match(summary, /sanitizer .* held back, not filed/);
    assert.match(summary, /fuzz-logs-standalone-config-commands-normal: no crash report/);
    assert.match(core.failed, /Held back 1 finding/);
    // A held-back finding has no would-be issue text.
    const ub = r.sanitizerFinding(data('ubsan-overflow.stderr')).signature;
    assert.equal(fs.existsSync(path.join(out, `${ub}.md`)), false);
    fs.rmSync(dir, {recursive: true});
});

test('posting comments on the matching issue and opens one for a new bug', async () => {
    const dir = makeUploads();
    const {github, calls} = fakeGitHub([{number: 42, body: `fuzzer-signature: ${canary()}`}]);
    const env = {FUZZ_FILE_ISSUES: 'true'};
    await r.run({github, context, core: fakeCore(), inputDir: path.join(dir, 'in'), outputDir: path.join(dir, 'out'), env});

    const comments = calls.filter((c) => c[0] === 'createComment');
    assert.equal(comments.length, 1);
    assert.equal(comments[0][1].issue_number, 42);
    assert.match(comments[0][1].body, /Seen again/);
    const created = calls.filter((c) => c[0] === 'create');
    assert.equal(created.length, 1);
    assert.equal(created[0][1].title, '[BUG] Fuzzer: malformed reply to FUNCTION LIST');
    assert.deepEqual(created[0][1].labels, ['fuzzer-crash']);
    assert.equal(calls.filter((c) => c[0] === 'createLabel').length, 1);
    fs.rmSync(dir, {recursive: true});
});

test('the same crash twice gives one issue, then one comment', async () => {
    const dir = makeUploads();
    const issues = [];
    const {github, calls} = fakeGitHub(issues);
    github.rest.issues.create = async (args) => {
        calls.push(['create', args]);
        issues.push({number: 100 + issues.length, body: args.body});
    };
    const env = {FUZZ_FILE_ISSUES: 'true'};
    const args = {github, context, core: fakeCore(), inputDir: path.join(dir, 'in'), outputDir: path.join(dir, 'out'), env};
    await r.run(args);
    await r.run(args);
    assert.equal(calls.filter((c) => c[0] === 'create').length, 2); // the canary assertion and FUNCTION LIST
    assert.equal(calls.filter((c) => c[0] === 'createComment').length, 2);
    fs.rmSync(dir, {recursive: true});
});

test('a dry run still works when issues can not be listed', async () => {
    const dir = makeUploads();
    const {github} = fakeGitHub([], {listFails: true});
    const result = await r.run({github, context, core: fakeCore(), inputDir: path.join(dir, 'in'), outputDir: path.join(dir, 'out'), env: {}});
    assert.match(result.summary, /Could not list issues/);
    await assert.rejects(r.run({github, context, core: fakeCore(), inputDir: path.join(dir, 'in'),
                                outputDir: path.join(dir, 'out'), env: {FUZZ_FILE_ISSUES: 'true'}}));
    fs.rmSync(dir, {recursive: true});
});
