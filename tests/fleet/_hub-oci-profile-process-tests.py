"""Controlled actual process custody; child stand-ins have no Worker/SDK code."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('profile_process', Path(__file__).with_name('_hub-oci-profile-process.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

NODE = os.environ.get('AOS_SOURCE_NODE')


def identity(pid):
    root=Path('/proc')/str(pid)
    with (root/'exe').open('rb') as stream:
        sha=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'pid':pid,'startTicks':(root/'stat').read_text().rpartition(') ')[2].split()[19],
        'ownerUid':root.stat().st_uid,'executableSha256':sha,
        'environmentSha256':hashlib.sha256((root/'environ').read_bytes()).hexdigest(),
        'commandLineSha256':hashlib.sha256((root/'cmdline').read_bytes()).hexdigest()}


class ProcessCustody(unittest.TestCase):
    def test_owned_actual_children_stop_before_exact_environment_restore(self):
        self.assertTrue(NODE and NODE.startswith('/nix/store/'))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            script=root/'runner.cjs'
            script.write_text("""
const fs=require('node:fs');
const child=require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});
child.once('exit',()=>process.exit(0));
process.once('SIGTERM',()=>child.kill('SIGTERM'));
fs.writeFileSync(process.argv[3],JSON.stringify({pid:child.pid}));
setInterval(()=>{},1000);
""")
            configuration={'host':'127.0.0.1','port':4645,'acceptanceSocketPath':str(root/'control.sock'),
                'resourcePersistencePath':str(root/'state'),'bindings':{
                    'HUB_EXTERNAL_URL':'https://localhost:4643',
                    'HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN':'https://localhost:4643'}}
            config=root/'configuration-A.json';helper.retained(config,json.dumps(configuration).encode())
            child_file=root/'actual-child.json'
            log=root/'A.log'
            with log.open('xb') as output:
                log.chmod(0o600)
                child=subprocess.Popen([NODE,str(script),str(config),str(child_file)],
                    env=dict(os.environ),stdout=output,stderr=subprocess.STDOUT)
            started=[]
            try:
                for _ in range(100):
                    if child_file.exists():break
                    time.sleep(.01)
                pin=identity(child.pid);pin['logFile']=str(log)
                workerd_standin=identity(json.loads(child_file.read_bytes())['pid'])
                capture=helper.capture_runner(root/'capture',pin,workerd_standin,str(config))
                raw=helper.private_file(capture['environment']['file'],helper.MAX_ENVIRONMENT)
                self.assertIn(b'HOME='+os.fsencode(os.environ['HOME'])+b'\0',raw)
                # Still-live originals forbid reuse of the same persistence.
                with self.assertRaises(ValueError):helper.launch_runner(capture,root,str(config),'premature')
                helper.stop_runner(capture,time.time()+5);self.assertEqual(child.wait(timeout=5),0)
                bfile=root/'configuration-B.json'
                helper.retained(bfile,json.dumps(helper.configuration_b(configuration)).encode())
                b=helper.launch_runner(capture,root,str(bfile),'B');started.append(b)
                time.sleep(.1)
                bchild=helper.workerd_child(b,pin['executableSha256'])
                bcapture={'runner':b,'workerd':bchild}
                self.assertEqual(helper.private_file(capture['environment']['file'],helper.MAX_ENVIRONMENT),raw)
                helper.stop_runner(bcapture,time.time()+5);os.waitpid(b['pid'],0);started.remove(b)
                restored=helper.launch_runner(capture,root,str(config),'A-restored');started.append(restored)
                time.sleep(.1)
                restored_child=helper.workerd_child(restored,pin['executableSha256'])
                self.assertEqual(restored['environmentSha256'],pin['environmentSha256'])
                helper.stop_runner({'runner':restored,'workerd':restored_child},time.time()+5)
                os.waitpid(restored['pid'],0);started.remove(restored)
            finally:
                if child.poll() is None:
                    child.terminate();child.wait(timeout=5)
                for pin in started:
                    os.kill(pin['pid'],15)
                    os.waitpid(pin['pid'],0)

    def test_malformed_or_changed_original_a_cannot_create_b(self):
        original={'host':'127.0.0.1','port':4645,'acceptanceSocketPath':'/private/control.sock',
            'bindings':{'HUB_EXTERNAL_URL':'https://localhost:4643',
                'HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN':'https://localhost:4643'}}
        for change in ('origin','port'):
            value=json.loads(json.dumps(original))
            if change=='origin':value['bindings']['HUB_EXTERNAL_URL']='https://unobserved.test'
            else:value['port']=4647
            with self.assertRaises(ValueError):helper.configuration_b(value)


if __name__=='__main__':
    unittest.main()
