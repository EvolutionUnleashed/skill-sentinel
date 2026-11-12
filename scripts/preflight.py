#!/usr/bin/env python3
"""Read-only, bounded inventory and verdict gate. Python 3.10+, POSIX.

Run a trusted copy with python3 -I -B, outside the untrusted target. No target
imports, execution, deserialization, archive extraction, config or dependencies.
This checks facts and report structure, not whether an agent's reasoning is true.
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

VERSION = 2
LIMITS = {'entries': 2000, 'file_bytes': 1024 * 1024,
          'total_bytes': 16 * 1024 * 1024, 'depth': 16, 'seconds': 15}
ARTIFACT_SUFFIXES = frozenset((
    '.pyc .pyo .exe .dll .so .dylib .pyd .class .jar .wasm .com .scr '
    '.o .obj .a .lib .zip .whl .egg .pyz .tar .gz .bz2 .xz .7z .rar '
    '.docm .xlsm .pptm .docx .xlsx .pptx .pdf .pkl .pickle .joblib .rds'
).split())
MAGICS = (b'\x7fELF', b'MZ', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
          b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xce',
          b'\xfe\xed\xfa\xcf', b'\x00asm', b'PK\x03\x04', b'PK\x05\x06',
          b'PK\x07\x08', b'\x1f\x8b', b'7z\xbc\xaf\x27\x1c', b'Rar!',
          b'\xfd7zXZ\x00', b'%PDF-')
SEVERITIES = {'NONE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True).encode()).hexdigest()


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def binary_reason(data, path, depth=0):
    """Conservative format screen, not a complete executable detector."""
    if any(s.lower() in ARTIFACT_SUFFIXES for s in Path(path).suffixes):
        return 'executable_or_container_name'
    if '__pycache__' in Path(path).parts:
        return 'python_cache_entry'
    pyc = (len(data) >= 4 and data[2:4] == b'\r\n' and
           (3000 <= int.from_bytes(data[:2], 'little') < 4000 or
            int.from_bytes(data[:2], 'little') >= 50000))
    if pyc or data.startswith(MAGICS) or data[257:262] == b'ustar':
        return 'executable_or_container_signature'
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return 'unsupported_binary_or_encoding'
    if any(ord(c) < 32 and c not in '\t\r\n\f' for c in text):
        return 'unsupported_binary_or_encoding'
    # Whole-file wrappers only. Embedded/novel encodings still need agent review.
    compact = text.strip().replace('\r', '').replace('\n', '')
    if compact:
        for decoder in (lambda s: base64.b64decode(s, validate=True), bytes.fromhex):
            try:
                decoded = decoder(compact)
            except (ValueError, binascii.Error):
                continue
            if decoded and depth >= 3:
                return 'encoding_nesting_limit'
            if decoded:
                reason = binary_reason(decoded, '', depth + 1)
                if reason in ('executable_or_container_signature', 'encoded_unverified_content',
                              'encoding_nesting_limit'):
                    return 'encoded_unverified_content'
    return None


def inventory(target):
    root = os.path.abspath(os.fspath(target))
    entries, blockers = [], []
    started, total = time.monotonic(), 0

    def block(path, reason):
        item = {'path': path, 'reason': reason}
        if item not in blockers:
            blockers.append(item)

    def budget():
        if time.monotonic() - started > LIMITS['seconds']:
            raise TimeoutError('inspection_time_limit')

    def visit(directory_fd, prefix='', depth=0):
        nonlocal total
        budget()
        before = os.fstat(directory_fd)
        if depth > LIMITS['depth']:
            block(prefix, 'nesting_limit')
            return
        # Never materialize an unbounded directory listing.
        with os.scandir(directory_fd) as listing:
            for child in listing:
                budget()
                if len(entries) >= LIMITS['entries']:
                    block(prefix, 'entry_limit')
                    return
                path = prefix + child.name
                item = {'path': path, 'kind': 'unresolved'}
                entries.append(item)
                try:
                    info = os.stat(child.name, dir_fd=directory_fd, follow_symlinks=False)
                    item.update(mode=stat.S_IMODE(info.st_mode), size=info.st_size)
                    if stat.S_ISLNK(info.st_mode):
                        item.update(kind='symlink', target=os.readlink(child.name, dir_fd=directory_fd))
                        block(path, 'symlink_requires_separate_review')
                    elif stat.S_ISDIR(info.st_mode):
                        item['kind'] = 'directory'
                        fd = os.open(child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=directory_fd)
                        try:
                            if fingerprint(os.fstat(fd)) != fingerprint(info):
                                block(path, 'changed_during_open')
                            else:
                                visit(fd, path + '/', depth + 1)
                        finally:
                            os.close(fd)
                    elif not stat.S_ISREG(info.st_mode):
                        item['kind'] = 'special'
                        block(path, 'special_file_not_opened')
                    elif info.st_nlink != 1:
                        item['kind'] = 'unresolved'
                        block(path, 'hardlink_not_opened')
                    elif info.st_size > LIMITS['file_bytes'] or total + info.st_size > LIMITS['total_bytes']:
                        item['kind'] = 'unresolved'
                        block(path, 'byte_limit')
                    else:
                        fd = os.open(child.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                     dir_fd=directory_fd)
                        try:
                            opened = os.fstat(fd)
                            if not stat.S_ISREG(opened.st_mode) or fingerprint(opened) != fingerprint(info):
                                item['kind'] = 'unresolved'
                                block(path, 'changed_during_open')
                                continue
                            chunks, count = [], 0
                            cap = min(LIMITS['file_bytes'], LIMITS['total_bytes'] - total)
                            while count <= cap:
                                budget()
                                data = os.read(fd, min(65536, cap + 1 - count))
                                if not data:
                                    break
                                chunks.append(data)
                                count += len(data)
                            total += count
                            final = os.fstat(fd)
                        finally:
                            os.close(fd)
                        data = b''.join(chunks)
                        if count > cap or fingerprint(info) != fingerprint(final) or count != info.st_size:
                            item['kind'] = 'unresolved'
                            block(path, 'changed_or_truncated_read')
                            continue
                        item['sha256'] = hashlib.sha256(data).hexdigest()
                        reason = binary_reason(data, path)
                        item['kind'] = 'unresolved' if reason else 'text'
                        if reason:
                            block(path, reason)
                except OSError as error:
                    item['kind'] = 'unresolved'
                    block(path, 'read_error:' + type(error).__name__)
        if fingerprint(before) != fingerprint(os.fstat(directory_fd)):
            block(prefix, 'directory_changed_during_scan')

    try:
        if not (hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY') and
                os.open in os.supports_dir_fd and os.scandir in os.supports_fd):
            block('.', 'unsupported_platform')
        else:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                root_info = os.fstat(fd)
                visit(fd)
                if fingerprint(root_info) != fingerprint(os.stat(root, follow_symlinks=False)):
                    block('.', 'root_changed_during_scan')
            finally:
                os.close(fd)
    except (OSError, TimeoutError) as error:
        block('.', 'inventory_error:' + type(error).__name__)
    if not any(item['path'] == 'SKILL.md' and item.get('kind') == 'text' for item in entries):
        block('SKILL.md', 'missing_or_unreadable_skill_entrypoint')
    entries.sort(key=lambda item: item['path'])
    blockers.sort(key=lambda item: (item['path'], item['reason']))
    manifest = {'schema_version': VERSION, 'root': root, 'limits': dict(LIMITS),
                'entries': entries, 'blockers': blockers}
    manifest['snapshot_id'] = digest(manifest)
    return manifest


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def gate(target, manifest, report):
    """Recompute facts from caller's target. Model-supplied verdicts are forbidden."""
    current = inventory(target)
    issues = list(current['blockers'])
    risks = []

    def reject(reason, path='.'):
        issues.append({'path': path, 'reason': reason})

    if manifest != current:
        reject('manifest_changed_or_invalid')
    if not isinstance(report, dict):
        report = {}
        reject('assessment_must_be_object')
    required = {'schema_version', 'snapshot_id', 'coverage', 'reviewed_files',
                'findings', 'unresolved', 'capabilities', 'dependencies',
                'categories_reviewed', 'executed_target'}
    if set(report) != required or type(report.get('schema_version')) is not int or report.get('schema_version') != VERSION:
        reject('assessment_schema_invalid')
    categories = report.get('categories_reviewed')
    if not isinstance(categories, list) or sorted(str(x) for x in categories) != [f'T{i}' for i in range(1, 9)]:
        reject('categories_incomplete_or_invalid')
    if report.get('executed_target') is not False:
        reject('target_execution_not_explicitly_false')
    if report.get('snapshot_id') != current['snapshot_id']:
        reject('assessment_snapshot_mismatch')
    if report.get('coverage') not in ('COMPLETE', 'INCOMPLETE'):
        reject('coverage_enum_invalid')
    elif report['coverage'] == 'INCOMPLETE':
        reject('agent_reports_incomplete')
    for key in ('reviewed_files', 'findings', 'unresolved', 'dependencies'):
        if not isinstance(report.get(key), list):
            report[key] = []
            reject(key + '_must_be_array')
    expected = {entry['path']: entry['sha256'] for entry in current['entries']
                if entry['kind'] == 'text'}
    seen = {}
    for item in report['reviewed_files']:
        if (not isinstance(item, dict) or set(item) != {'path', 'sha256'} or
                not isinstance(item['path'], str) or not isinstance(item['sha256'], str)):
            reject('reviewed_file_invalid')
            continue
        path = item['path']
        if path in seen or expected.get(path) != item['sha256']:
            reject('reviewed_file_unknown_duplicate_or_changed', path)
        seen[path] = item['sha256']
    if seen != expected:
        reject('reviewed_files_do_not_cover_snapshot')
    for finding in report['findings']:
        fields = {'category', 'severity', 'confidence', 'path', 'evidence', 'reason', 'recommendation'}
        if (not isinstance(finding, dict) or set(finding) != fields or
                not all(nonempty(value) for value in finding.values()) or
                finding['category'] not in {f'T{i}' for i in range(1, 9)} or
                finding['severity'] not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') or
                finding['confidence'] not in ('LOW', 'MEDIUM', 'HIGH')):
            reject('finding_invalid')
            continue
        risks.append(finding['severity'])
    for gap in report['unresolved']:
        if not isinstance(gap, dict) or set(gap) != {'path', 'reason'} or not all(nonempty(v) for v in gap.values()):
            reject('gap_invalid')
        else:
            reject('agent_gap:' + gap['reason'], gap['path'])
    capabilities = report.get('capabilities')
    if (not isinstance(capabilities, dict) or set(capabilities) != {'reads', 'writes', 'network', 'executes'} or
            not all(isinstance(v, list) and all(nonempty(s) for s in v) for v in capabilities.values())):
        reject('capabilities_invalid')
    for dependency in report['dependencies']:
        if (not isinstance(dependency, dict) or set(dependency) != {'reference', 'path'} or
                not nonempty(dependency['reference']) or not isinstance(dependency['path'], str)):
            reject('dependency_invalid')
        elif dependency['path'] not in expected or dependency['path'] not in seen:
            reject('unresolved_runtime_dependency:' + dependency['reference'])
    observed = max(risks, key=SEVERITIES.get, default='NONE')
    complete = not issues
    decision = ('BLOCK' if not complete or SEVERITIES[observed] >= 3 else
                'REVIEW' if risks else 'PROCEED')
    rating = ('CRITICAL' if observed == 'CRITICAL' else 'HIGH' if not complete else
              observed if risks else 'CLEAN')
    return {'schema_version': VERSION, 'snapshot_id': current['snapshot_id'],
            'coverage': 'COMPLETE' if complete else 'INCOMPLETE',
            'observed_risk': observed, 'decision': decision, 'overall_rating': rating,
            'blockers': issues}


def read_control(path, root):
    # Operator-owned controls must be outside the untrusted package.
    if os.path.commonpath((os.path.realpath(path), os.path.realpath(root))) == os.path.realpath(root):
        raise ValueError('control_file_inside_target')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('control_file_not_regular')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(2 * 1024 * 1024 + 1)
    finally:
        os.close(fd)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError('control_file_too_large')

    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate_json_key')
            value[key] = item
        return value

    def constant(value):
        raise ValueError('nonfinite_json_number')
    return json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    scan = sub.add_parser('inventory')
    scan.add_argument('target')
    check = sub.add_parser('gate')
    check.add_argument('target')
    check.add_argument('--manifest', required=True)
    check.add_argument('--assessment', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'inventory':
            result = inventory(args.target)
            code = 2 if result['blockers'] else 0
        else:
            result = gate(args.target, read_control(args.manifest, args.target),
                          read_control(args.assessment, args.target))
            code = {'PROCEED': 0, 'REVIEW': 1, 'BLOCK': 2}[result['decision']]
    except (OSError, ValueError, RecursionError, AttributeError, TypeError) as error:
        result = {'schema_version': VERSION, 'coverage': 'INCOMPLETE',
                  'observed_risk': 'UNKNOWN', 'decision': 'BLOCK', 'overall_rating': 'HIGH',
                  'blockers': [{'path': '.', 'reason': 'control_error:' + type(error).__name__}]}
        code = 2
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True))
    return code


if __name__ == '__main__':
    sys.exit(main())
