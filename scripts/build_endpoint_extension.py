#!/usr/bin/env python3
"""Build a reviewable .systemextension bundle. Never install/activate or change SIP."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--release', action='store_true')
parser.add_argument('--identity', help='Developer ID Application signing identity')
parser.add_argument('--profile', type=Path, help='Apple-approved Endpoint Security provisioning profile')
args = parser.parse_args()
if bool(args.identity) != bool(args.profile):
    parser.error('--identity and --profile must be supplied together')
if args.profile and not args.profile.is_file():
    parser.error('provisioning profile does not exist')
root = Path(__file__).resolve().parent.parent
cargo = shutil.which('cargo') or str(Path.home() / '.cargo/bin/cargo')
environment = dict(os.environ)
environment['MACOSX_DEPLOYMENT_TARGET'] = '12.0'
command = [cargo, 'build', '-p', 'monitor-enforcer']
if args.release:
    command.append('--release')
subprocess.run(command, cwd=root, env=environment, check=True)
variant = 'release' if args.release else 'debug'
bundle = root / 'target' / 'system-extensions' / variant / 'dev.agentmonitor.endpoint.systemextension'
contents = bundle / 'Contents'
(contents / 'MacOS').mkdir(parents=True, exist_ok=True)
shutil.copy2(root / 'target' / variant / 'monitor-enforcer', contents / 'MacOS' / 'monitor-enforcer')
shutil.copy2(root / 'native/macos/endpoint/Info.plist', contents / 'Info.plist')
profile = contents / 'embedded.provisionprofile'
if profile.exists():
    profile.unlink()
if args.identity:
    shutil.copy2(args.profile, profile)
    subprocess.run(['/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp', '--sign', args.identity,
                    '--entitlements', str(root / 'native/macos/endpoint/entitlements.plist'), str(bundle)], check=True)
    subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(bundle)], check=True)
else:
    # An earlier signed bundle must not retain a misleading signature after rebuild.
    signature = contents / '_CodeSignature'
    if signature.exists():
        shutil.rmtree(signature)
    print('Unsigned development bundle: cannot activate without Apple-approved signing/profile.')
print(bundle)
