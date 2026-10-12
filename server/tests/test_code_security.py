"""
server/tests/test_code_security.py — regresiones del módulo Code Security
(diagnóstico del reporte real de DVWA: Dependency-Check "completed" con BD vacía,
estados falsos, reglas de Semgrep perdidas, hallazgos fundidos, nota incoherente).

Solo `unittest` (igual que test_skill_executor.py). Usa binarios FALSOS (scripts de
shell en un PATH temporal) para ejercitar los wrappers reales sin instalar
Semgrep/Dependency-Check.

    cd server && python3 -m unittest tests.test_code_security -v
"""
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.code_security import dependency_check as dc            # noqa: E402
from modules.code_security import semgrep_scanner as sg              # noqa: E402
from modules.code_security.orchestrator import CodeScanOrchestrator  # noqa: E402
from modules.code_security.backdoor_scanner import BackdoorScanner   # noqa: E402
import findings as findings_module                                    # noqa: E402
from utils.scoring import calculate_grade, calculate_score_from_findings  # noqa: E402

REPORT = {'dependencies': [{
    'fileName': 'lib.jar', 'filePath': '/x/lib.jar', 'packages': [{'id': 'pkg:maven/a/b@1'}],
    'vulnerabilities': [
        {'name': 'CVE-2020-1', 'severity': 'MODERATE', 'cvssv3': {'baseScore': 5.5}, 'description': 'd'},
        {'name': 'CVE-2020-2', 'severity': 'HIGH', 'cvssv3': {'baseScore': 8.1}, 'description': 'd'},
    ]}]}


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.bin = self.tmp / 'bin'; self.bin.mkdir()
        self.code = self.tmp / 'code'; self.code.mkdir()
        (self.code / 'a.php').write_text("<?php\n$c = shell_exec('ping ' . $t);\n")
        p = mock.patch.dict(os.environ, {'PATH': f'{self.bin}:{os.environ["PATH"]}'})
        p.start(); self.addCleanup(p.stop)

    def fake_bin(self, name, body):
        f = self.bin / name
        f.write_text('#!/bin/sh\n' + body + '\n')
        f.chmod(f.stat().st_mode | stat.S_IEXEC)


class TestDependencyCheck(_Base):
    def dc_env(self, body, db_bytes):
        data = self.tmp / 'dcdata'; data.mkdir()
        if db_bytes:
            (data / 'odc.mv.db').write_bytes(b'0' * db_bytes)
        for target, val in (('_DATA_DIR', str(data)), ('_MIN_DB_BYTES', 1024), ('_LOCK_WAIT', 2)):
            p = mock.patch.object(dc, target, val); p.start(); self.addCleanup(p.stop)
        dc._update_state['running'] = False
        self.fake_bin('dependency-check.sh', body)
        return data

    def test_db_missing_is_skipped_not_completed(self):
        self.dc_env('exit 0', 0)
        with mock.patch.object(dc, 'ensure_database', return_value=False):
            r = dc.DependencyCheckScanner(timeout=10).scan(str(self.code))
        self.assertEqual(r['status'], 'skipped')
        self.assertIn('no está inicializada', r['error'])
        self.assertEqual(r['findings'], [])

    def test_runs_noupdate_with_data_dir_and_parses(self):
        args_log = self.tmp / 'args.txt'
        body = (f'echo "$@" > {args_log}\nOUT=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && OUT="$2"; shift; done\n'
                f'cat > "$OUT/dependency-check-report.json" <<\'JSON\'\n{json.dumps(REPORT)}\nJSON')
        data = self.dc_env(body, 4096)
        r = dc.DependencyCheckScanner(timeout=20).scan(str(self.code))
        args = args_log.read_text()
        self.assertIn('--noupdate', args)
        self.assertIn(f'--data {data}', args)
        self.assertEqual((r['status'], r['error']), ('completed', None))
        self.assertEqual([f['severity'] for f in r['findings']], ['medium', 'high'])  # MODERATE -> medium
        self.assertEqual(r['dependencies_analyzed'], 1)

    def test_timeout_kills_whole_process_group(self):
        pidfile = self.tmp / 'child.pid'
        self.dc_env(f'sleep 60 &\necho $! > {pidfile}\nwait', 4096)
        t0 = time.time()
        r = dc.DependencyCheckScanner(timeout=2).scan(str(self.code))
        self.assertLess(time.time() - t0, 15)
        self.assertEqual(r['status'], 'timeout')
        time.sleep(0.5)
        pid = int(pidfile.read_text())
        try:  # un zombi (muerto pero sin recolectar por init del contenedor) cuenta como muerto
            state = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
        except FileNotFoundError:
            state = 'gone'
        self.assertIn(state, ('Z', 'gone'))  # el hijo (JVM) también murió

    def test_node_audit_is_opt_in(self):
        args_log = self.tmp / 'args.txt'
        body = (f'echo "$@" > {args_log}\nOUT=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && OUT="$2"; shift; done\n'
                f'echo \'{{"dependencies": []}}\' > "$OUT/dependency-check-report.json"')
        self.dc_env(body, 4096)
        dc.DependencyCheckScanner(timeout=20).scan(str(self.code))
        self.assertIn('--disableNodeAudit', args_log.read_text())
        with mock.patch.dict(os.environ, {'DEPENDENCY_CHECK_NODE_AUDIT': 'true'}):
            r = dc.DependencyCheckScanner(timeout=20).scan(str(self.code))
        self.assertNotIn('--disableNodeAudit', args_log.read_text())
        self.assertTrue(r['node_audit'])

    def test_respects_timeout_parameter(self):
        self.assertEqual(dc.DependencyCheckScanner(timeout=77).timeout, 77)  # antes se forzaba a 10800

    def test_lock_contention_is_skipped(self):
        data = self.dc_env('exit 0', 4096)
        held = dc._FileLock(str(data / '.depcheck.lock'))
        self.assertTrue(held.acquire(0))
        try:
            r = dc.DependencyCheckScanner(timeout=10).scan(str(self.code))
        finally:
            held.release()
        self.assertEqual(r['status'], 'skipped')
        self.assertIn('en uso', r['error'])


class TestSemgrep(_Base):
    def rules(self):
        rules = self.tmp / 'rules'; rules.mkdir(); (rules / 'r.yaml').write_text('rules: []')
        p = mock.patch.object(sg, '_RULES_DIR', str(rules)); p.start(); self.addCleanup(p.stop)

    def test_relative_paths_dedupe_and_real_warning(self):
        self.rules()
        res = {'results': [
            {'path': f'{self.code}/a.php', 'check_id': 'opt.semgrep-rules.exec-use', 'start': {'line': 2, 'col': 1},
             'extra': {'message': 'm', 'severity': 'ERROR', 'metadata': {'cwe': ['CWE-94']}}},
            {'path': f'{self.code}/a.php', 'check_id': 'opt.semgrep-rules.exec-use', 'start': {'line': 2, 'col': 1},
             'extra': {'message': 'm', 'severity': 'ERROR', 'metadata': {}}}],
            'errors': [{'type': 'PartialParsing', 'level': 'warn', 'message': 'x'},
                       {'type': 'RuleParseError', 'level': 'error', 'message': 'bad rule foo'}],
            'paths': {'scanned': ['a.php']}}
        self.fake_bin('semgrep', 'OUT=""; while [ $# -gt 0 ]; do [ "$1" = "--output" ] && OUT="$2"; shift; done\n'
                                 f'cat > "$OUT" <<\'JSON\'\n{json.dumps(res)}\nJSON')
        r = sg.SemgrepScanner(timeout=20).scan(str(self.code))
        self.assertEqual((r['status'], r['error']), ('completed', None))
        self.assertEqual(len(r['findings']), 1)                 # duplicado eliminado
        self.assertEqual(r['findings'][0]['file'], 'a.php')     # sin prefijo /tmp/codescan-...
        self.assertEqual(r['findings'][0]['rule'], 'exec-use')
        self.assertIn('1 error', r['warning'])
        self.assertIn('bad rule foo', r['warning'])             # PartialParsing se ignora
        self.assertEqual(r['rules_loaded'], 1)

    def test_cwe_owasp_always_lists(self):
        # Regresión: reglas con cwe/owasp como string suelto rompían .map() en el frontend
        self.rules()
        res = {'results': [
            {'path': f'{self.code}/a.js', 'check_id': 'js.x', 'start': {'line': 1, 'col': 1},
             'extra': {'message': 'm', 'severity': 'WARNING', 'metadata': {'cwe': 'CWE-79: XSS', 'owasp': 'A03:2021 - Injection'}}},
            {'path': f'{self.code}/b.js', 'check_id': 'js.y', 'start': {'line': 2, 'col': 1},
             'extra': {'message': 'm', 'severity': 'WARNING', 'metadata': {}}}], 'errors': [], 'paths': {'scanned': []}}
        self.fake_bin('semgrep', 'OUT=""; while [ $# -gt 0 ]; do [ "$1" = "--output" ] && OUT="$2"; shift; done\n'
                                 f'cat > "$OUT" <<\'JSON\'\n{json.dumps(res)}\nJSON')
        r = sg.SemgrepScanner(timeout=20).scan(str(self.code))
        self.assertEqual(r['findings'][0]['cwe'], ['CWE-79: XSS'])
        self.assertEqual(r['findings'][0]['owasp'], ['A03:2021 - Injection'])
        self.assertEqual(r['findings'][1]['cwe'], [])

    def test_missing_report_surfaces_stderr(self):
        self.rules()
        self.fake_bin('semgrep', 'echo "boom: invalid config" >&2\nexit 2')
        r = sg.SemgrepScanner(timeout=20).scan(str(self.code))
        self.assertEqual(r['status'], 'error')
        self.assertIn('boom: invalid config', r['error'])


class TestTruffleHog(_Base):
    LINE = json.dumps({'DetectorName': 'AWS', 'Raw': 'AKIAXXXXXXXXXXXXXXXX', 'Verified': False,
                       'SourceMetadata': {'Data': {'Git': {'file': 'a.js', 'line': 3, 'commit': 'abc'}}}})

    def test_timeout_keeps_partial_findings(self):
        from modules.code_security.trufflehog_scanner import TruffleHogScanner
        self.fake_bin('trufflehog', f"echo '{self.LINE}'\nsleep 30")
        r = TruffleHogScanner(timeout=2, verify=False).scan(str(self.code))
        self.assertEqual(r['status'], 'timeout')
        self.assertEqual(len(r['findings']), 1)             # lo hallado antes del timeout se conserva
        self.assertIn('parcial', r['error'])

    def test_real_failure_is_error_not_clean(self):
        from modules.code_security.trufflehog_scanner import TruffleHogScanner
        self.fake_bin('trufflehog', 'echo "unknown flag" >&2\nexit 1')
        r = TruffleHogScanner(timeout=10, verify=False).scan(str(self.code))
        self.assertEqual(r['status'], 'error')
        self.assertIn('unknown flag', r['error'])

    def test_non_finding_json_lines_ignored(self):
        from modules.code_security.trufflehog_scanner import _parse_findings
        out = '{"level":"info-0","msg":"finished scanning"}\n' + self.LINE + '\nnot json\n'
        self.assertEqual(len(_parse_findings(out)), 1)


class _Fake:
    def __init__(self, result=None, exc=None):
        self.result, self.exc = result, exc

    def scan(self, path):
        if self.exc:
            raise self.exc
        return dict(self.result)


class TestOrchestrator(unittest.TestCase):
    def test_real_status_per_tool_and_failure_isolation(self):
        o = CodeScanOrchestrator.__new__(CodeScanOrchestrator)
        fakes = {
            'semgrep': _Fake({'findings': [{'file': 'a', 'line': 1, 'rule_id': 'r', 'severity': 'high'}] * 2, 'error': None}),
            'trivy': _Fake(exc=RuntimeError('db corrupta')),
            'dependency_check': _Fake({'findings': [], 'error': 'BD NVD vacía', 'status': 'skipped'}),
        }
        # 7 herramientas desde que se añadió 'crypto_keys' (material criptográfico)
        for k in ('gitleaks', 'trufflehog', 'backdoors', 'semgrep', 'trivy', 'dependency_check', 'crypto_keys'):
            setattr(o, k, fakes.get(k) or _Fake({'findings': [], 'error': None}))
        started, done = [], {}
        out = o.scan_directory(tempfile.mkdtemp(), on_start=started.append,
                               on_done=lambda k, r: done.update({k: r['status']}))
        self.assertEqual(sorted(started), sorted(done))
        self.assertEqual(len(done), 7)
        self.assertEqual(done['trivy'], 'error')
        self.assertIn('db corrupta', out['trivy']['error'])
        self.assertEqual(done['dependency_check'], 'skipped')
        self.assertEqual((done['gitleaks'], done['semgrep']), ('completed', 'completed'))
        self.assertEqual(out['summary']['high'], 1)             # duplicado no cuenta dos veces
        self.assertEqual(out['summary']['tools_completed'], 5)
        self.assertEqual(out['summary']['tools_total'], 7)
        self.assertEqual(set(out['summary']['tools_failed']), {'Trivy', 'Dependency-Check'})
        self.assertTrue(all('duration_s' in out[k] for k in ('gitleaks', 'trivy', 'dependency_check')))


class TestFindingsScoreBackdoors(unittest.TestCase):
    def test_dependency_findings_not_collapsed(self):
        scan = {'scan_type': 'code', 'dependency_check': {'findings': [
            {'file': 'lib.jar', 'package': 'p', 'vuln_id': 'CVE-1', 'severity': 'high'},
            {'file': 'lib.jar', 'package': 'p', 'vuln_id': 'CVE-2', 'severity': 'high'},
            {'file': 'lib.jar', 'package': 'p', 'vuln_id': 'CVE-3', 'severity': 'critical'}]}}
        out = findings_module.dedupe_findings(findings_module.normalize_findings(scan))
        self.assertEqual({f['cve'] for f in out}, {'CVE-1', 'CVE-2', 'CVE-3'})

    def test_same_cve_different_package_versions_not_merged(self):
        # Regresión del reporte de NodeGoat: minimist x4 versiones contaba como 1 crítico
        fs = [{'target': 'package-lock.json', 'package': 'minimist', 'installed_version': v,
               'vuln_id': 'CVE-2021-44906', 'severity': 'critical'} for v in ('0.0.8', '0.0.10', '1.2.0', '1.2.5')]
        fs.append(dict(fs[0]))  # duplicado REAL (misma versión): este sí se fusiona
        scan = {'scan_type': 'code', 'trivy': {'findings': fs}}
        out = findings_module.dedupe_findings(findings_module.normalize_findings(scan))
        self.assertEqual(len(out), 4)
        o = CodeScanOrchestrator.__new__(CodeScanOrchestrator)
        self.assertEqual(o._build_summary({'trivy': {'findings': fs}})['critical'], 4)

    def test_two_semgrep_rules_same_line_kept(self):
        scan = {'scan_type': 'code', 'semgrep': {'findings': [
            {'file': 'a.php', 'line': 5, 'rule_id': 'x.exec-use', 'severity': 'high'},
            {'file': 'a.php', 'line': 5, 'rule_id': 'x.tainted-exec', 'severity': 'high'}]}}
        self.assertEqual(len(findings_module.normalize_findings(scan)), 2)

    def test_grade_never_better_than_score(self):
        bd = {'critical': 0, 'high': 65, 'medium': 0, 'low': 0, 'info': 0}
        self.assertEqual(calculate_grade(0, bd)[0], 'F')        # antes: 'C' con puntaje 0
        r = calculate_score_from_findings([{'severity': 'high', 'tool': 'semgrep'}] * 63)
        self.assertEqual(r['grade'], 'F')
        self.assertEqual(r['breakdown']['high'], 63)            # breakdown real, no recortado

    def test_backdoor_ignores_prose_and_comments_keeps_real_calls(self):
        d = Path(tempfile.mkdtemp())
        (d / 'help.php').write_text(
            "<p>Execute on the target system (such as <?php x('system()'); ?>) ok</p>\n"
            "<p>file system (load_file) and more</p>\n// eval($x);\n# shell_exec('ls');\n")
        (d / 'real.php').write_text("<?php\n$o = shell_exec('ping ' . $t);\nreturn exec($c);\n")
        r = BackdoorScanner().scan(str(d))
        self.assertEqual({(f['file'], f['line']) for f in r['findings']}, {('real.php', 2), ('real.php', 3)})


if __name__ == '__main__':
    unittest.main()
