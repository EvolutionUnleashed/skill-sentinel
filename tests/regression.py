"""Benign corpus builder and report assertions; this is NOT a scanner.

Only compile fixed, locally authored constant assignments. Never execute/import the
resulting fixtures or unmarshal bytecode. Python 3.8+, standard library only.
"""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import py_compile
import struct
import tempfile
import unittest
import zipfile

SOURCE = "VALUE = 'source-only'\n"
COMPILED = "VALUE = 'compiled-only'\n"
BLOCKED = {name: artifact for name, artifact in [
    ('unchecked_decoy', '__pycache__/helper.pyc'),
    ('checked_cache', '__pycache__/helper.pyc'),
    ('timestamp_cache', '__pycache__/helper.pyc'),
    ('sourceless', 'helper.pyc'),
    ('renamed_bytecode', 'assets/data.bin'),
    ('legacy_bytecode', 'helper.pyo'),
    ('native_placeholder', 'helper.so'),
    ('wasm', 'helper.wasm'),
    ('archive', 'bundle.zip'),
    ('encoded_bytecode', 'payload.txt'),
    ('unknown_format', 'assets/data'),
    ('invalid_bytecode', 'helper.pyc'),
]}
CONTROLS = ('text_only', 'source_only', 'image_asset')


def write(root, relative, data):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode('utf-8')
    path.write_bytes(data)


def build(root):
    """Require a new destination to avoid overwriting an existing corpus."""
    root.mkdir(parents=True, exist_ok=False)
    for name in (*CONTROLS, *BLOCKED):
        write(root / name, 'SKILL.md',
              '---\nname: fixture\ndescription: A local formatting helper.\n---\n'
              '# Fixture\nFormat supplied text as a numbered list.\n')
    write(root / 'source_only', 'helper.py', SOURCE)
    # A locally authored, inert SVG; the documented role is display only.
    write(root / 'image_asset', 'icon.svg',
          '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">'
          '<rect width="1" height="1" fill="green"/></svg>\n')
    write(root / 'image_asset', 'README.md', 'Display icon.svg as the skill icon.\n')
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary)
        for case, mode in [
            ('unchecked_decoy', py_compile.PycInvalidationMode.UNCHECKED_HASH),
            ('checked_cache', py_compile.PycInvalidationMode.CHECKED_HASH),
            ('timestamp_cache', py_compile.PycInvalidationMode.TIMESTAMP),
        ]:
            src = staging / 'helper.py'
            src.write_text(COMPILED if case == 'unchecked_decoy' else SOURCE,
                           encoding='utf-8')
            output = root / case / BLOCKED[case]
            output.parent.mkdir(parents=True, exist_ok=True)
            py_compile.compile(str(src), cfile=str(output), dfile='helper.py',
                               doraise=True, invalidation_mode=mode)
            write(root / case, 'helper.py', SOURCE)
    bytecode = (root / 'unchecked_decoy' / BLOCKED['unchecked_decoy']).read_bytes()
    for case in ('sourceless', 'renamed_bytecode', 'legacy_bytecode'):
        write(root / case, BLOCKED[case], bytecode)
    write(root / 'renamed_bytecode', 'README.md', 'assets/data.bin is bundled helper data.\n')
    # Intentionally incomplete ELF-like bytes: no native executable payload.
    write(root / 'native_placeholder', 'helper.so', b'\x7fELF' + bytes(28))
    # Valid empty WASM module with no functions, imports, or start section.
    write(root / 'wasm', 'helper.wasm', b'\x00asm\x01\x00\x00\x00')
    with zipfile.ZipFile(root / 'archive' / 'bundle.zip', 'w') as archive:
        archive.writestr('helper.py', SOURCE)
        archive.writestr('__pycache__/helper.pyc', bytecode)
    write(root / 'encoded_bytecode', 'payload.txt', base64.b64encode(bytecode))
    write(root / 'unknown_format', 'assets/data', b'\x00\xff\x81unknown\x00')
    write(root / 'invalid_bytecode', 'helper.pyc', b'\x00\x00')


def check_reports(reports):
    """Check independently produced agent results, never manufacture verdicts."""
    expected = set(CONTROLS) | set(BLOCKED)
    if not isinstance(reports, dict) or set(reports) != expected:
        raise ValueError('Report must contain exactly the 15 corpus case names')
    for name, result in reports.items():
        if name in CONTROLS:
            if result.get('status') != 'COMPLETE' or result.get('risk') != 'CLEAN':
                raise ValueError(f'{name}: benign control was not COMPLETE/CLEAN')
            if result.get('gaps') != []:
                raise ValueError(f'{name}: unexpected coverage gap')
        else:
            if result.get('status') != 'INCOMPLETE' or result.get('risk') != 'HIGH':
                raise ValueError(f'{name}: expected INCOMPLETE/HIGH, not a clean bill')
            if BLOCKED[name] not in result.get('gaps', []):
                raise ValueError(f'{name}: missing artifact coverage gap')
        if result.get('executed_target') is not False:
            raise ValueError(f'{name}: target execution must be explicitly false')


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'corpus'
        build(self.root)

    def test_modes_and_decoy_are_real(self):
        for case, flags in [('unchecked_decoy', 1), ('checked_cache', 3),
                            ('timestamp_cache', 0)]:
            blob = (self.root / case / BLOCKED[case]).read_bytes()
            self.assertEqual(blob[:4], importlib.util.MAGIC_NUMBER)
            self.assertEqual(struct.unpack('<I', blob[4:8])[0], flags)
            self.assertGreater(len(blob), 16)
        unchecked = (self.root / 'unchecked_decoy' / BLOCKED['unchecked_decoy']).read_bytes()
        self.assertEqual(unchecked[8:16], importlib.util.source_hash(COMPILED.encode()))
        self.assertNotEqual(unchecked[8:16], importlib.util.source_hash(SOURCE.encode()))
        self.assertEqual((self.root / 'unchecked_decoy/helper.py').read_text(), SOURCE)

    def test_alternate_representations(self):
        original = (self.root / 'unchecked_decoy' / BLOCKED['unchecked_decoy']).read_bytes()
        for case in ('sourceless', 'renamed_bytecode', 'legacy_bytecode'):
            self.assertEqual((self.root / case / BLOCKED[case]).read_bytes(), original)
        self.assertEqual(base64.b64decode((self.root / 'encoded_bytecode/payload.txt').read_bytes()), original)
        with zipfile.ZipFile(self.root / 'archive/bundle.zip') as archive:
            self.assertEqual(archive.read('__pycache__/helper.pyc'), original)

    def test_corpus_has_only_expected_cases(self):
        self.assertEqual({p.name for p in self.root.iterdir()}, set(CONTROLS) | set(BLOCKED))
        with self.assertRaises(FileExistsError):
            build(self.root)

    def test_report_checker_rejects_original_false_negative(self):
        # This tests the assertion harness, not the scanner or a model.
        reports = {name: {'status': 'COMPLETE', 'risk': 'CLEAN', 'gaps': [],
                          'executed_target': False} for name in (*CONTROLS, *BLOCKED)}
        with self.assertRaises(ValueError):
            check_reports(reports)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, help='Create benign corpus in a NEW directory')
    parser.add_argument('--check', type=Path, help='Validate independently produced report JSON')
    args = parser.parse_args()
    if args.build and args.check:
        parser.error('Choose --build or --check')
    if args.build:
        build(args.build)
        print(f'Created 15 benign cases in {args.build}')
    elif args.check:
        check_reports(json.loads(args.check.read_text(encoding='utf-8')))
        print('PASS: 15 independent reports satisfy the classification contract')
    else:
        unittest.main(argv=['regression.py'])
