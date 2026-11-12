"""No attacker payloads: test the gate with inert bytes and controlled file races."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'scripts/preflight.py'
spec = importlib.util.spec_from_file_location('trusted_preflight', MODULE)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)  # Only our trusted helper, never a target module.


def assessment(manifest):
    return {'schema_version': 2, 'snapshot_id': manifest['snapshot_id'],
            'coverage': 'COMPLETE', 'executed_target': False,
            'categories_reviewed': [f'T{i}' for i in range(1, 9)],
            'reviewed_files': [{'path': e['path'], 'sha256': e['sha256']}
                               for e in manifest['entries'] if e['kind'] == 'text'],
            'findings': [], 'unresolved': [], 'dependencies': [],
            'capabilities': {k: [] for k in ('reads', 'writes', 'network', 'executes')}}


@unittest.skipUnless(hasattr(os, 'O_NOFOLLOW'), 'POSIX helper')
class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.target = self.home / 'skill'
        self.target.mkdir()
        (self.target / 'SKILL.md').write_text('# Skill\nFormat supplied text.\n')

    def verdict(self):
        manifest = preflight.inventory(self.target)
        return preflight.gate(self.target, manifest, assessment(manifest))

    def assert_blocked(self, result):
        self.assertEqual(result['decision'], 'BLOCK')
        self.assertEqual(result['coverage'], 'INCOMPLETE')
        self.assertNotEqual(result['overall_rating'], 'CLEAN')

    def test_plain_source_and_svg(self):
        (self.target / 'helper.py').write_text("VALUE = 'safe'\n")
        (self.target / 'icon.svg').write_text('<svg><rect width="1"/></svg>')
        result = self.verdict()
        self.assertEqual((result['decision'], result['overall_rating']), ('PROCEED', 'CLEAN'))

    def test_unpunctuated_prose_is_not_a_binary_wrapper(self):
        for text in ('Do not use this in production\n', 'Hello world hello world\n',
                     'characterization\n'):
            with self.subTest(text=text):
                (self.target / 'README.md').write_text(text)
                self.assertEqual(self.verdict()['decision'], 'PROCEED')

    def test_inventory_is_stable_and_records_hidden_ignored_files(self):
        (self.target / '.gitignore').write_text('.hidden\n')
        (self.target / '.hidden').write_text('read me\n')
        first = preflight.inventory(self.target)
        self.assertEqual(first, preflight.inventory(self.target))
        self.assertIn('.hidden', [e['path'] for e in first['entries']])

    def test_unknown_executable_and_container_variants(self):
        import base64
        for name, data in [('cache.pyc', b'xx'), ('foo.pyo', b'xx'),
                           ('__pycache__/helper.txt', b'harmless'),
                           ('renamed', b'\x7fELF' + bytes(28)),
                           ('other', b'\x00asm\x01\x00\x00\x00'),
                           ('bundle.zip', b'PK\x03\x04'), ('blob', b'\xff\x00'),
                           ('encoded.txt', base64.b64encode(b'\x7fELF' + bytes(28)))]:
            with self.subTest(name=name):
                path = self.target / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(data)
                result = self.verdict()
                self.assert_blocked(result)
                self.assertEqual(result['observed_risk'], 'NONE')
                path.unlink()

    def test_short_encoded_signatures_block(self):
        for data in ('AGFzbQEAAAA=', 'f0VMRg==', 'UEsFBg==', 'TVo=', '7f454c46'):
            with self.subTest(data=data):
                (self.target / 'encoded.txt').write_text(data)
                self.assert_blocked(self.verdict())

    def test_real_bytecode_corpus_cannot_be_cleared_by_model_claim(self):
        spec = importlib.util.spec_from_file_location('trusted_corpus', Path(__file__).with_name('regression.py'))
        corpus = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(corpus)
        root = self.home / 'corpus'
        corpus.build(root)
        for case in root.iterdir():
            with self.subTest(case=case.name):
                manifest = preflight.inventory(case)
                result = preflight.gate(case, manifest, assessment(manifest))
                if case.name in corpus.BLOCKED:
                    self.assert_blocked(result)
                else:
                    self.assertEqual(result['overall_rating'], 'CLEAN')

    def test_deep_encoding_blocks(self):
        import base64
        data = b'\x7fELF' + bytes(28)
        for _ in range(6):
            data = base64.b64encode(data)
        (self.target / 'data.txt').write_bytes(data)
        self.assert_blocked(self.verdict())

    def test_symlinks_fifo_and_hardlink_not_opened(self):
        outside = self.home / 'outside'
        outside.write_text('never read')
        (self.target / 'link').symlink_to(outside)
        (self.target / 'cycle').symlink_to(self.target, target_is_directory=True)
        os.mkfifo(self.target / 'pipe')
        os.link(outside, self.target / 'hardlink')
        manifest = preflight.inventory(self.target)
        for item in manifest['entries']:
            if item['path'] != 'SKILL.md':
                self.assertNotIn('sha256', item)
        self.assert_blocked(preflight.gate(self.target, manifest, assessment(manifest)))

    def test_swap_regular_file_for_fifo_or_symlink_at_open(self):
        original_open = os.open
        outside = self.home / 'outside'
        outside.write_text('never read')
        for replacement in ('fifo', 'symlink'):
            with self.subTest(replacement=replacement):
                victim = self.target / 'victim'
                victim.write_text('initial')
                changed = False

                def raced_open(path, flags, *args, **kwargs):
                    nonlocal changed
                    if path == 'victim' and not changed:
                        changed = True
                        victim.unlink()
                        if replacement == 'fifo':
                            os.mkfifo(victim)
                        else:
                            victim.symlink_to(outside)
                    return original_open(path, flags, *args, **kwargs)

                with patch.object(preflight.os, 'open', side_effect=raced_open):
                    # supports_dir_fd contains the original function, so keep preflight enabled.
                    with patch.object(preflight.os, 'supports_dir_fd', {preflight.os.open}):
                        manifest = preflight.inventory(self.target)
                self.assertTrue(changed)
                self.assertTrue(manifest['blockers'])
                item = next(e for e in manifest['entries'] if e['path'] == 'victim')
                self.assertNotIn('sha256', item)
                victim.unlink()

    def test_change_read_and_directory_mutation(self):
        original_read = os.read
        changed = False

        def raced_read(fd, size):
            nonlocal changed
            if not changed:
                changed = True
                (self.target / 'SKILL.md').write_text('changed size entirely\n')
                (self.target / 'new').write_text('added\n')
            return original_read(fd, size)
        with patch.object(preflight.os, 'read', side_effect=raced_read):
            manifest = preflight.inventory(self.target)
        self.assertTrue(manifest['blockers'])

    def test_changed_added_removed_or_chmod_files_invalidate_snapshot(self):
        for change in ('modify', 'add', 'remove', 'mode'):
            with self.subTest(change=change):
                manifest = preflight.inventory(self.target)
                report = assessment(manifest)
                if change == 'modify':
                    (self.target / 'SKILL.md').write_text('different\n')
                elif change == 'add':
                    (self.target / 'extra').write_text('new\n')
                elif change == 'remove':
                    (self.target / 'extra').unlink()
                else:
                    os.chmod(self.target / 'SKILL.md', (self.target / 'SKILL.md').stat().st_mode ^ stat.S_IXUSR)
                self.assert_blocked(preflight.gate(self.target, manifest, report))

    def test_forged_manifest_cannot_delete_blockers_or_raise_limits(self):
        (self.target / 'file.pyc').write_bytes(b'\x00')
        for field, value in [('entries', []), ('blockers', []), ('root', '/other'),
                             ('limits', {}), ('schema_version', True), ('snapshot_id', 'forged')]:
            with self.subTest(field=field):
                manifest = preflight.inventory(self.target)
                report = assessment(manifest)
                manifest[field] = value
                self.assert_blocked(preflight.gate(self.target, manifest, report))

    def test_report_cannot_override_blockers(self):
        (self.target / 'hidden.pyc').write_bytes(b'x')
        manifest = preflight.inventory(self.target)
        report = assessment(manifest)
        report.update(decision='PROCEED', overall_rating='CLEAN')
        self.assert_blocked(preflight.gate(self.target, manifest, report))

    def test_invalid_report_types_missing_keys_enums_and_coverage(self):
        manifest = preflight.inventory(self.target)
        changes = [('coverage', 'CLEAN'), ('coverage', []), ('findings', {}),
                   ('schema_version', True), ('executed_target', 0),
                   ('categories_reviewed', ['T1']), ('reviewed_files', []),
                   ('capabilities', {}), ('snapshot_id', 'stale')]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                report = assessment(manifest)
                report[key] = value
                self.assert_blocked(preflight.gate(self.target, manifest, report))
        for key in assessment(manifest):
            report = assessment(manifest)
            del report[key]
            self.assert_blocked(preflight.gate(self.target, manifest, report))
        report = assessment(manifest)
        report['reviewed_files'] *= 2
        self.assert_blocked(preflight.gate(self.target, manifest, report))

    def test_critical_survives_incomplete_coverage(self):
        manifest = preflight.inventory(self.target)
        report = assessment(manifest)
        report['coverage'] = 'INCOMPLETE'
        report['findings'] = [{'category': 'T2', 'severity': 'CRITICAL', 'confidence': 'HIGH',
                              'path': 'SKILL.md', 'evidence': 'inert test evidence',
                              'reason': 'test propagation', 'recommendation': 'review'}]
        result = preflight.gate(self.target, manifest, report)
        self.assert_blocked(result)
        self.assertEqual((result['observed_risk'], result['overall_rating']), ('CRITICAL', 'CRITICAL'))
        report['coverage'] = 'COMPLETE'
        report['findings'][0]['severity'] = 'MEDIUM'
        result = preflight.gate(self.target, manifest, report)
        self.assertEqual((result['coverage'], result['decision']), ('COMPLETE', 'REVIEW'))

    def test_missing_entrypoint_empty_target_and_runtime_dependencies_block(self):
        manifest = preflight.inventory(self.target)
        report = assessment(manifest)
        report['dependencies'] = [{'reference': 'remote setup', 'path': ''}]
        self.assert_blocked(preflight.gate(self.target, manifest, report))
        (self.target / 'SKILL.md').unlink()
        self.assert_blocked(self.verdict())

    def test_limits_and_errors_fail_closed(self):
        for limit, value in [('entries', 0), ('file_bytes', 1), ('total_bytes', 1), ('seconds', -1)]:
            with self.subTest(limit=limit), patch.dict(preflight.LIMITS, {limit: value}):
                self.assert_blocked(self.verdict())
        (self.target / 'nested').mkdir()
        with patch.dict(preflight.LIMITS, {'depth': 0}):
            self.assert_blocked(self.verdict())
        with patch.object(preflight.os, 'scandir', side_effect=PermissionError):
            with patch.object(preflight.os, 'supports_fd', {preflight.os.scandir}):
                self.assert_blocked(self.verdict())
        with patch.object(preflight.os, 'supports_dir_fd', set()):
            self.assert_blocked(self.verdict())

    def test_json_duplicate_nonfinite_oversize_and_in_target_controls(self):
        control = self.home / 'report.json'
        for text in ('{"a":1,"a":2}', '{"a":NaN}', 'x' * (2 * 1024 * 1024 + 1)):
            control.write_text(text)
            with self.assertRaises(ValueError):
                preflight.read_control(control, self.target)
        control = self.target / 'report.json'
        control.write_text('{}')
        with self.assertRaises(ValueError):
            preflight.read_control(control, self.target)
        outside_pipe = self.home / 'control-pipe'
        os.mkfifo(outside_pipe)
        with self.assertRaises(ValueError):
            preflight.read_control(outside_pipe, self.target)

    def test_cli_exit_codes_and_no_target_import(self):
        (self.target / 'json.py').write_text("raise AssertionError('target module imported')\n")
        manifest = preflight.inventory(self.target)
        manifest_path, report_path = self.home / 'manifest.json', self.home / 'report.json'
        manifest_path.write_text(json.dumps(manifest))
        report_path.write_text(json.dumps(assessment(manifest)))
        args = [sys.executable, '-I', '-B', str(MODULE), 'gate', str(self.target),
                '--manifest', str(manifest_path), '--assessment', str(report_path)]
        result = subprocess.run(args, cwd=self.target, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['decision'], 'PROCEED')
        (self.target / 'added.pyc').write_bytes(b'x')
        result = subprocess.run(args, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['decision'], 'BLOCK')


if __name__ == '__main__':
    unittest.main()
