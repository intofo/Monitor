#!/usr/bin/env python3
"""Build/sign the network system extension, without installing or activating it."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
parser=argparse.ArgumentParser()
parser.add_argument('--release',action='store_true')
parser.add_argument('--identity')
parser.add_argument('--profile',type=Path)
args=parser.parse_args()
if bool(args.identity)!=bool(args.profile):parser.error('--identity and --profile are required together')
if args.profile and not args.profile.is_file():parser.error('Provisioning profile does not exist')
root=Path(__file__).resolve().parents[1]
cargo=shutil.which('cargo') or str(Path.home()/'.cargo/bin/cargo')
env=dict(os.environ,MACOSX_DEPLOYMENT_TARGET='12.0')
subprocess.run([cargo,'build','-p','monitor-enforcer','--lib']+(['--release'] if args.release else []),cwd=root,env=env,check=True)
variant='release' if args.release else 'debug'
bundle=root/'target/system-extensions'/variant/'dev.agentmonitor.network.systemextension'
contents=bundle/'Contents'
(contents/'MacOS').mkdir(parents=True,exist_ok=True)
subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-mmacosx-version-min=12.0','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations',
    str(root/'native/macos/network/Filter.m'),str(root/'target'/variant/'libmonitor_enforcer.a'),
    '-framework','NetworkExtension','-framework','Foundation','-framework','Security','-framework','CoreFoundation','-lEndpointSecurity','-lbsm',
    '-o',str(contents/'MacOS/monitor-network')],check=True)
shutil.copy2(root/'native/macos/network/Info.plist',contents/'Info.plist')
profile=contents/'embedded.provisionprofile'
profile.unlink(missing_ok=True)
if args.identity:
    shutil.copy2(args.profile,profile)
    subprocess.run(['codesign','--force','--options','runtime','--timestamp','--sign',args.identity,'--entitlements',str(root/'native/macos/network/entitlements.plist'),str(bundle)],check=True)
    subprocess.run(['codesign','--verify','--strict',str(bundle)],check=True)
else:
    shutil.rmtree(contents/'_CodeSignature',ignore_errors=True)
    print('Unsigned network extension. Signing and user approval are still required.')
print(bundle)
