"""Controlled same-source assessment and exact launch-config boundaries."""

import copy
import importlib.util
from pathlib import Path
import unittest


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


fixture = module('profile_fixture', '_hub-oci-profile-mismatch.py')
process = module('profile_process', '_hub-oci-profile-process.py')


def evidence():
    original = {'issuer': {'source_digest': '1'*64, 'script_version':'actual-script'},
        'nonce':'2'*64, 'key':'real/prefix/oci/uploads/retained/chunk',
        'descriptor':{'digest':'sha256:'+'3'*64}, 'protected_profile_digest':'4'*64,
        'issued_at':100, 'expires_at':130, 'clock_uncertainty_seconds':1}
    counter = {'isolateId':'actual-selected-isolate', 'maximum':2, 'active':0,
        'bulkActive':0,'metadataActive':0,'peakActive':0,'metadataAdmissionsDuringBulk':0,'dispatches':0}
    entry = {'kind':'entry','original':{'nonce':original['nonce'],'key':original['key'],
        'document_digest':original['descriptor']['digest'],'expires_at':130,
        'request_sha256':'6'*64,'issued_at':100,'clock_uncertainty_seconds':1,
        'source_digest':'1'*64,'script_version':'actual-script','protected_profile_digest':'4'*64},'before':counter}
    artifact = {'kind':'artifact','artifact_sha256':'5'*64,'byte_size':1234,
        'deployment_id':'actual-deployment','current_origin':'https://localhost:4643',
        'artifact_origin':'https://localhost:4643','source_digest':'1'*64,
        'script_version':'actual-script','profile_digest':'4'*64,'verification_now':110,
        'artifact_issued_at':90,'artifact_expires_at':140}
    events = [entry,artifact,{'kind':'result','outcome':'accepted','error':None},
        {'kind':'terminal','outcome':'accepted','healthy':True,'after':copy.deepcopy(counter)}]
    a = [{'version':1,'scope':'managed_oci_profile_load','capture_id':'a'*32,'ordinal':i+1,
          'request_sha256':'6'*64,'observed_at':110,'event':event} for i,event in enumerate(events)]
    b = copy.deepcopy(a)
    for row in b: row['request_sha256']='7'*64
    b[0]['event']['original']['request_sha256']='7'*64
    b[1]['event']['current_origin']='https://localhost:4648'
    b[2]['event'].update(outcome='refused',error='OCI SDK acceptance audience, facts or original window differs')
    b[3]['event']['outcome']='refused'
    observation = {'origin':'https://localhost:4643','sourceDigest':'1'*64,'scriptVersion':'actual-script',
        'wasmSha256':'8'*64,'runnerSha256':'9'*64,'configurationSha256':'a'*64,'pid':100}
    observed = {'a':observation,'b':{**observation,'origin':'https://localhost:4648','pid':200,
                                   'configurationSha256':'b'*64}}
    return original,a,b,observed


class Assessment(unittest.TestCase):
    def assess(self, original, a, b, observations):
        return fixture.assess_profile_origin_mismatch(original,'7'*64,'5'*64,a,b,observations)

    def test_equal_source_origin_change_with_complete_actual_counter_shape(self):
        original,a,b,observed=evidence()
        self.assertEqual(self.assess(original,a,b,observed)['scope'],
            'authenticated_physical_key_loader_interval_only')

    def test_source_difference_is_not_relabelled_as_this_case(self):
        original,a,b,observed=evidence();observed['b']['sourceDigest']='f'*64
        with self.assertRaises(ValueError): self.assess(original,a,b,observed)

    def test_missing_cancelled_extra_or_counter_gap_is_unknown(self):
        for kind in ('missing','cancelled','extra','dispatch','isolate','expired','artifact-expired','capture','entry-extra','observation-extra'):
            with self.subTest(kind=kind):
                original,a,b,observed=evidence()
                if kind=='missing': b.pop()
                if kind=='cancelled': b[3]['event']['healthy']=False
                if kind=='extra': b[3]['event']['zero']=0
                if kind=='dispatch': b[3]['event']['after']['dispatches']=1
                if kind=='isolate': b[3]['event']['after']['isolateId']='other'
                if kind=='expired': b[3]['observed_at']=129
                if kind=='capture': b[2]['capture_id']='b'*32
                if kind=='entry-extra': b[0]['event']['original']['callerPass']=True
                if kind=='observation-extra': observed['b']['sdkZero']=True
                if kind=='artifact-expired': b[1]['event']['artifact_expires_at']=110
                with self.assertRaises(ValueError): self.assess(original,a,b,observed)

    def test_other_installed_artifact_or_original_nonce_refuses(self):
        for kind in ('artifact','nonce','origin'):
            original,a,b,observed=evidence()
            if kind=='artifact': b[1]['event']['artifact_sha256']='0'*64
            if kind=='nonce': b[0]['event']['original']['nonce']='0'*64
            if kind=='origin': b[1]['event']['current_origin']='https://unobserved.test'
            with self.assertRaises(ValueError): self.assess(original,a,b,observed)

    def test_actual_sql_projection_is_exact_and_stale_rows_refuse(self):
        original,_,_,_=evidence()
        original['descriptor']['size']=32
        original['admission']={'upload_id':'actual-upload','original_digest':'f'*64,
            'byte_size':32,'placement_prefix':'real/prefix','staging_object_key':'oci/uploads/retained/chunk'}
        rows={'upload':{'id':'actual-upload','writer_id':'actual-token','token_id':'actual-token',
            'idempotency_key':'manifest-hybrid-'+ 'f'*64+'-'+ '0'*32,'state':'active','expires_at':140,
            'expected_digest':original['descriptor']['digest'],'expected_size':32,
            'staging_placement_id':1,'staging_placement_resource_version':2,
            'staging_binding_id':3,'staging_binding_write_revision':4},
            'chunk':{'ordinal':0,'upload_id':'actual-upload','staging_object_key':'oci/uploads/retained/chunk',
                'byte_size':32,'digest':original['descriptor']['digest']},
            'placement':{'id':1,'resource_version':2,'binding_id':3,'prefix':'real/prefix'},
            'binding':{'id':3,'write_revision':4}}
        fixture.check_profile_original_rows(original,rows,110)
        for section,field,value in [('upload','state','complete'),('placement','resource_version',3),
                ('chunk','staging_object_key','other'),('binding','write_revision',5),('upload','expires_at',109)]:
            altered=copy.deepcopy(rows);altered[section][field]=value
            with self.assertRaises(ValueError): fixture.check_profile_original_rows(original,altered,110)


    def test_selected_context_uses_actual_shared_digest_and_clock_namespace_join(self):
        original,a,_,observed=evidence()
        selector={'version':1,'capture_id':'a'*32,'placement_prefix':'real/prefix',
            'document_digest':original['descriptor']['digest']}
        configuration={'bindings':{'HUB_OCI_PROFILE_LOAD_OBSERVER':selector}}
        namespace={'observationScope':'oci_sdk_emulator_namespace_readback','runnerPid':100,
            'runnerStartTicks':'123','buildDerivedSourceDigest':'1'*64,
            'buildDerivedScriptVersion':'actual-script','wasmSha256':'8'*64,
            'runnerSha256':'9'*64,'configurationSha256':'a'*64}
        identity={'sourceDigest':'1'*64,'scriptVersion':'actual-script'}
        arguments={'prepared':{'coordinates':{'gcPrefix':'real/prefix'}},
            'worker_a':{'pid':100,'startTicks':'123'},'configuration_file':'/private/config',
            'namespace_file':'/private/namespace','artifact_sha256':'5'*64,
            'listener':{'root':'/private/listener'}}
        selected=fixture._select_context_records(configuration,namespace,identity,{'6'*64:a},**arguments)
        self.assertEqual(selected['selection']['protected_profile_digest'],a[1]['event']['profile_digest'])
        self.assertEqual(selected['observationA'],observed['a'])
        for kind in ('missing','clock','artifact','profile','capture'):
            modified=copy.deepcopy(a);clock=copy.deepcopy(identity)
            if kind=='missing': modified.pop()
            if kind=='clock': clock['sourceDigest']='f'*64
            if kind=='artifact': modified[1]['event']['artifact_sha256']='f'*64
            if kind=='profile': modified[1]['event']['profile_digest']='f'*64
            if kind=='capture': modified[0]['capture_id']='b'*32
            with self.assertRaises(ValueError):
                fixture._select_context_records(configuration,namespace,clock,{'6'*64:modified},**arguments)

    def test_b_preserves_persistence_roles_source_and_actual_a_original(self):
        original={'host':'127.0.0.1','port':4645,'resourcePersistencePath':'/var/lib/fresh/state',
            'name':'selected-worker','scriptPath':'/nix/store/selected/shim',
            'acceptanceSocketPath':'/var/lib/fresh/control.sock',
            'bindings':{'HUB_EXTERNAL_URL':'https://localhost:4643',
                'HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN':'https://localhost:4643',
                'HUB_DIRECT_UPLOAD_GUARD_KEY':'private-role','HUB_HYBRID_ORIGIN_URL':'https://localhost:4644'}}
        saved=copy.deepcopy(original);candidate=process.configuration_b(original)
        self.assertEqual(original,saved)
        self.assertEqual(candidate['resourcePersistencePath'],original['resourcePersistencePath'])
        self.assertEqual(candidate['bindings']['HUB_DIRECT_UPLOAD_GUARD_KEY'],'private-role')
        self.assertEqual(candidate['bindings']['HUB_HYBRID_ORIGIN_URL'],'https://localhost:4644')
        self.assertEqual(candidate['bindings']['HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN'],'https://localhost:4648')
        self.assertEqual(candidate['port'],4647)


if __name__ == '__main__':
    unittest.main()
