"""Run: python -m unittest discover -s tests -p 'test_firmware_ssid_update.py' -v
No Flask, database, or network services required for these focused unit tests.
"""
import ast
import importlib.util
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import MagicMock
from tempfile import TemporaryDirectory
from datetime import datetime, timedelta

ROOT = Path(__file__).resolve().parents[1]
FW = ROOT / 'captive-portal/app/blueprints/admin'
PORTAL = ROOT / 'captive-portal/app/blueprints/portal.py'


def load_notices():
    spec = importlib.util.spec_from_file_location('firmware_notices', FW / 'firmware_notices.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def extract_function(filename, name, bindings):
    tree = ast.parse(filename.read_text(encoding='utf-8'))
    node = next(n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
    node.decorator_list = []
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(filename), 'exec'), bindings)
    return bindings[name]


class FirmwareNoticeTests(TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.previous = os.environ.get('GIT_REPO_DIR')
        os.environ['GIT_REPO_DIR'] = self.tmp.name
        self.mod = load_notices()

    def tearDown(self):
        if self.previous is None:
            os.environ.pop('GIT_REPO_DIR', None)
        else:
            os.environ['GIT_REPO_DIR'] = self.previous
        self.tmp.cleanup()

    def test_multi_commit_retains_order_and_reloads(self):
        def manifest(comment):
            return {'post_update': {'commands': [f'echo {comment}'], 'description': comment}}
        self.assertTrue(self.mod.record_step('update', 'aaaaaaa11', 'bbbbbbb22', manifest('first')))
        self.assertTrue(self.mod.record_step('update', 'bbbbbbb22', 'ccccccc33', manifest('second')))
        self.assertEqual([n['commands'][0] for n in load_notices().pending_notices()],
                         ['echo first', 'echo second'])
        self.assertFalse(self.mod.record_step('update', 'aaaaaaa11', 'bbbbbbb22', manifest('first')))
        self.assertEqual(len(self.mod.pending_notices()), 2)

    def test_acknowledgement_is_explicit_and_persistent(self):
        for a, b in [('aaaaaaa','bbbbbbb'), ('bbbbbbb','ccccccc')]:
            self.mod.record_step('update', a, b, {'post_update': {'commands':['true']}})
        ids = [n['id'] for n in self.mod.pending_notices()]
        self.assertEqual(self.mod.acknowledge_notices([ids[0]]), 1)
        self.assertEqual([n['id'] for n in load_notices().pending_notices()], [ids[1]])
        self.assertEqual(self.mod.acknowledge_notices(ids), 1)
        self.assertEqual(self.mod.pending_notices(), [])
        self.assertFalse(self.mod.record_step('update','aaaaaaa','bbbbbbb', {'post_update': {'commands':['true']}}))

    def test_missing_commands_and_fallback(self):
        self.assertFalse(self.mod.record_step('update','aaaaaaa','bbbbbbb', {}))
        self.assertEqual(self.mod.pending_notices(), [])
        self.mod.record_fallback('update','aaaaaaa','bbbbbbb',['.','captive-portal'])
        notices = self.mod.pending_notices()
        self.assertEqual(len(notices), 1)
        self.assertIn('captive-portal', notices[0]['notes'])

    def test_update_latest_sse_retains_each_commit_notice(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        status={
            'current_full':'aaaaaaa111',
            'commits_ahead':[
                {'full':'bbbbbbb222','from_full':'aaaaaaa111','short':'bbbbbbb','subject':'First'},
                {'full':'ccccccc333','from_full':'bbbbbbb222','short':'ccccccc','subject':'Second'},
            ],
            'latest_full':'ccccccc333','latest_dirs':['.'],
        }
        class FakeSession(dict):
            modified = False
        session=FakeSession(firmware_preflight_approved='update-latest')
        class FakeProcess:
            stdout=['checkout ok\n']
            returncode=0
            def wait(self):return 0
        fake_subprocess=SimpleNamespace(Popen=lambda *a,**kw:FakeProcess(), PIPE=-1, STDOUT=-2)
        manifests={
            'aaaaaaa111':{'post_update':{'commands':['echo first']}},
            'bbbbbbb222':{'post_update':{'commands':['echo second']}},
        }
        bindings={
            'session':session,
            'json':json,
            'os':os,
            '_run_firmware_script':lambda action:SimpleNamespace(returncode=0,stdout=json.dumps(status)),
            '_load_commit_manifest':lambda tree, old: manifests.get(old),
            '_materialize_migration_script':lambda *a:None,
            '_remove_env_vars':lambda keys:None,
            'subprocess':fake_subprocess,
            'record_step':self.mod.record_step,
            'record_fallback':self.mod.record_fallback,
            'pending_notices':self.mod.pending_notices,
            'Response':lambda generator, **kwargs:generator,
            'stream_with_context':lambda generator:generator,
            'jsonify':lambda x:x,
        }
        stream = extract_function(FW / 'firmware.py', 'stream', bindings)
        events=list(stream('update-latest'))
        self.assertIn('data: __EXIT__:0\n\n', events)
        pending=self.mod.pending_notices()
        self.assertEqual([x['commands'] for x in pending],[['echo first'],['echo second']])
        self.assertEqual([x['to_commit'] for x in pending],['bbbbbbb','ccccccc'])

    def test_corruption_is_not_silently_cleared(self):
        path = Path(self.mod._path())
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text('{not json}')
        with self.assertRaises(json.JSONDecodeError):
            self.mod.record_step('update','aaaaaaa','bbbbbbb', {'post_update': {'commands':['echo test']}})
        self.assertEqual(path.read_text(), '{not json}')

    def test_manifest_for_current_head(self):
        manifest = json.loads((ROOT/'captive-portal/commit-migrations/1d7eb6a.json').read_text())
        cmds = manifest['post_update']['commands']
        self.assertNotIn('docker compose run --rm npm-setup',cmds)
        self.assertIn('docker compose up -d --build --no-deps web',cmds)


class SSIDReassignmentTests(TestCase):
    def test_intent_requires_current_device_vlan_and_unexpired_window(self):
        bindings = {'datetime':datetime, 'time':time, 'session':{}}
        helper = extract_function(PORTAL, '_reassignment_intent', bindings)
        now = time.time()
        bindings['session']['portal_reassignment']={'mac':'AA','vlan':21,'expires':now+300}
        self.assertIsNotNone(helper('AA',21))
        self.assertIsNone(helper('AA',11))
        self.assertNotIn('portal_reassignment', bindings['session'])
        bindings['session']['portal_reassignment']={'mac':'AA','vlan':21,'expires':now-1}
        self.assertIsNone(helper('AA',21))

    def _route_env(self, conn='wifi', permission=True, pending=False):
        owner = SimpleNamespace(id=7,email='owner@example.test',blocked=False)
        device = SimpleNamespace(mac_address='AA',assigned_vlan=11,
                                 internet_blocked=False,device_name='laptop')
        rq = MagicMock()
        rq.filter_by.return_value.order_by.return_value.first.return_value = (
            SimpleNamespace(approval_token='test-token', id=42) if pending else None
        )
        bindings = {
            'get_client_mac':lambda:'AA',
            'Device':SimpleNamespace(query=SimpleNamespace(filter_by=lambda **kwargs:SimpleNamespace(first=lambda:device))),
            'get_active_ownership':lambda mac:SimpleNamespace(user_id=7),
            'User':SimpleNamespace(query=SimpleNamespace(get=lambda uid:owner)),
            'get_client_ip':lambda:'192.168.21.101',
            'detect_connection_type':lambda ip:(conn,21,'Guest'),
            'portal_host_mismatch':lambda:False,
            'build_portal_url':lambda path:path,
            'get_vlan_map':lambda:{'Staff':11,'Guest':21},
            'get_wired_unregistered_vlan_id':lambda:250,
            'RegistrationRequest':SimpleNamespace(query=rq, submitted_at=SimpleNamespace(desc=lambda:None)),
            'session':{}, 'flash':MagicMock(), 'redirect':lambda url:url,
            'url_for':lambda endpoint, **kwargs:'/register' if endpoint=='portal.register' else '/wrong-vlan',
            'datetime':datetime, 'time':time, 'os':os,
            'urlparse':lambda value:SimpleNamespace(scheme='https', netloc='portal.example.test'),
            'send_admin_notification':MagicMock(return_value=1),
            'logger':MagicMock(),
            'get_ssid_for_vlan':lambda vlan:'Guest',
        }
        bindings['_pending_request_for_vlan'] = extract_function(PORTAL,'_pending_request_for_vlan',bindings)
        route = extract_function(PORTAL,'wrong_vlan_request_change',bindings)
        return route,bindings,owner,device

    def test_button_starts_registration_without_granting_vlan(self):
        route,b,owner,device=self._route_env()
        result=route()
        self.assertEqual(result,'/register')
        self.assertEqual(b['session']['portal_reassignment']['vlan'],21)
        self.assertEqual(device.assigned_vlan,11)

    def test_wired_change_is_blocked_but_existing_target_request_can_resend_email(self):
        route,b,_,_=self._route_env(conn='wired')
        self.assertEqual(route(),'/wrong-vlan')
        self.assertFalse(b['session'])
        route,b,_,_=self._route_env(pending=True)
        self.assertEqual(route(),'/wrong-vlan')
        self.assertFalse(b['session'])
        b['send_admin_notification'].assert_called_once()
        b['flash'].assert_called_once()

    def test_wrong_vlan_detection_helper_redirect_condition(self):
        helper = extract_function(PORTAL, '_is_registered_device_on_wrong_wifi', {})
        registered = SimpleNamespace(registration_status='registered', assigned_vlan=11)
        self.assertTrue(helper(registered, 'wifi', 21, False))
        self.assertFalse(helper(registered, 'wifi', 11, False))
        self.assertFalse(helper(registered, 'wired', 21, False))
        self.assertFalse(helper(registered, 'wifi', 21, True))

    def test_register_get_redirects_registered_device_to_wrong_vlan_page(self):
        device = SimpleNamespace(
            mac_address='AA', assigned_vlan=11, registration_status='registered',
            internet_blocked=False, user=SimpleNamespace(email='owner@example.test'),
        )
        owner = SimpleNamespace(user_id=7)
        bindings = {
            'request':SimpleNamespace(method='GET', headers={}, query_string=b''),
            'get_client_mac':lambda:'AA', 'get_client_ip':lambda:'192.168.21.101',
            'detect_connection_type':lambda ip:('wifi',21,'Guest'),
            'get_wired_unregistered_vlan_id':lambda:250,
            'get_wired_assignable_entries':lambda:[], 'get_vlan_map':lambda:{'Staff':11,'Guest':21},
            'Device':SimpleNamespace(query=SimpleNamespace(filter_by=lambda **kw:SimpleNamespace(first=lambda:device))),
            'get_active_ownership':lambda mac:owner,
            'normalize_device_status':lambda value:value,
            'portal_host_mismatch':lambda:False,
            '_reassignment_intent':lambda mac,vlan:None,
            '_is_registered_device_on_wrong_wifi':extract_function(PORTAL,'_is_registered_device_on_wrong_wifi',{}),
            'url_for':lambda endpoint, **kwargs:'/wrong-vlan',
            'redirect':lambda target:('redirect',target),
        }
        route=extract_function(PORTAL,'register',bindings)
        self.assertEqual(route(),('redirect','/wrong-vlan'))

    def test_pending_request_lookup_is_scoped_to_exact_target_vlan(self):
        seen = {}
        class Query:
            def filter_by(self, **kwargs):
                seen.update(kwargs)
                return self
            def order_by(self, *args):
                return self
            def first(self):
                return 'matching request'
        bindings = {'RegistrationRequest':SimpleNamespace(query=Query(), submitted_at=SimpleNamespace(desc=lambda:None))}
        helper = extract_function(PORTAL, '_pending_request_for_vlan', bindings)
        self.assertEqual(helper('AA', 21), 'matching request')
        self.assertEqual(seen, {'mac_address':'AA', 'requested_vlan':21, 'status':'pending'})

    def _registration_env(self, allow):
        import secrets
        owner = SimpleNamespace(id=7,email='owner@example.test',first_name='Lee',
                                last_name='Tester',phone_number='', blocked=False,
                                has_network_password=False, require_approval_every_device=False,
                                network_password_approval_mode=None)
        device = SimpleNamespace(mac_address='AA',assigned_vlan=11,current_vlan=11,
                internet_blocked=False,device_name='laptop',registration_status='registered',
                connection_type='wifi',ssid='Staff', is_wired=False,profile_snapshot=None,
                unregister_token='existing-token', ownership_validated=True,
                user=owner, internet_accessible=False)
        rq = MagicMock()
        rq.filter_by.return_value.first.return_value=None
        approvals_sent = MagicMock()
        confirmation_sent = MagicMock()
        session = {'portal_reassignment':{
                'mac':'AA','vlan':21,'expires':time.time()+300}}
        request = SimpleNamespace(method='POST', headers={'X-Requested-With':'XMLHttpRequest'},
            form={'registration_step':'2','email':'owner@example.test',
                  'first_name':'Lee','last_name':'Tester','device_type':'laptop'},
            args={})
        bindings = {
            'request':request,'session':session,'logger':MagicMock(),
            'get_client_mac':lambda:'AA','get_client_ip':lambda:'192.168.21.101',
            'get_wired_unregistered_vlan_id':lambda:250,
            'get_wired_assignable_entries':lambda:[],
            'get_wired_assignable_vlan_ids':lambda:set(),
            'get_vlan_map':lambda:{'Staff':11,'Guest':21},
            'detect_connection_type':lambda ip:('wifi',21,'Guest'),
            'Device':SimpleNamespace(query=SimpleNamespace(filter_by=lambda **kw:SimpleNamespace(first=lambda:device))),
            'User':SimpleNamespace(query=SimpleNamespace(
                filter_by=lambda **kw:SimpleNamespace(first=lambda:owner),
                get=lambda uid:owner)),
            'RegistrationRequest':MagicMock(query=rq),
            'get_active_ownership':lambda mac:SimpleNamespace(user_id=7),
            'get_effective_vlans_for_user':lambda u,m:({21},set()) if allow else (set(),set()),
            'load_domain_policy_map':lambda:{},
            'vlan_requires_password':lambda vlan:False,
            'get_ssid_for_vlan':lambda vlan:'Guest' if vlan==21 else 'Staff',
            '_hydrate_user_from_central':lambda email:(None,None),
            '_build_prefill_from_request':lambda:{},
            'db':SimpleNamespace(session=MagicMock()),
            'is_blocked_pool_ip':lambda ip:False,
            '_get_kea':lambda:None,
            '_should_hijack_vlan':lambda vlan:False,
            'manage_switch_acl':MagicMock(),
            'get_active_iplease':lambda mac:None,
            'set_internet_accessible':lambda d, allowed, commit: setattr(d,'internet_accessible',allowed),
            'clear_unregistered_lease':MagicMock(),
            'build_unregister_url':lambda token:'/unregister/'+token,
            'set_wifi_confirmation':lambda device:(None,None,None),
            'wifi_confirm_timeout_minutes':lambda:2,
            'send_wifi_registration_confirmation':confirmation_sent,
            'send_admin_notification':approvals_sent,
            'central_client':SimpleNamespace(queue_device_registered=MagicMock()),
            'secrets':secrets, 'json':json, 'datetime':datetime, 'time':time,
            'os':os, 'urlparse':lambda x:None,
            'url_for':lambda endpoint,**kwargs:'/approve' if 'approve' in endpoint else '/register',
            'jsonify':lambda x:x,
            'redirect':lambda x:x,
            'flash':MagicMock(),
            'portal_host_mismatch':lambda:False,
            'render_template':MagicMock(),
        }
        bindings['_reassignment_intent'] = extract_function(PORTAL,'_reassignment_intent',bindings)
        return extract_function(PORTAL,'register',bindings), bindings, device, rq, approvals_sent, confirmation_sent

    def test_reassignment_auto_approves_permitted_vlan(self):
        register,b,device,rq,notifications,confirmation=self._registration_env(True)
        answer=register()
        self.assertEqual(answer['status'],'registered')
        self.assertEqual(device.assigned_vlan,21)
        self.assertEqual(device.current_vlan,21)
        self.assertTrue(device.internet_accessible)
        self.assertFalse(answer['network_mismatch'])
        self.assertNotIn('portal_reassignment',b['session'])
        notifications.assert_not_called()
        confirmation.assert_called_once()

    def test_reassignment_forbidden_vlan_requests_admin(self):
        register,b,device,rq,notifications,confirmation=self._registration_env(False)
        answer=register()
        self.assertEqual(answer['status'],'pending')
        self.assertEqual(device.assigned_vlan,11)
        self.assertNotIn('portal_reassignment',b['session'])
        notifications.assert_called_once()
        confirmation.assert_not_called()

    def test_owner_every_device_approval_overrides_allowed_vlan(self):
        register,b,device,rq,notifications,confirmation=self._registration_env(True)
        b['User'].query.get(7).require_approval_every_device = True
        answer=register()
        self.assertEqual(answer['status'],'pending')
        self.assertEqual(device.assigned_vlan,11)
        notifications.assert_called_once()

    def test_admin_notification_queue_failure_is_reported(self):
        register,b,device,rq,notifications,confirmation=self._registration_env(False)
        notifications.return_value = 0
        answer=register()
        self.assertEqual(answer['status'],'pending')
        self.assertTrue(any(
            'administrator notification could not be queued' in str(call)
            for call in b['flash'].call_args_list
        ))

    def test_reassignment_expiry_does_not_silently_switch(self):
        register,b,device,rq,notifications,confirmation=self._registration_env(True)
        b['session']['portal_reassignment']['expires']=time.time()-10
        answer,status=register()
        self.assertEqual(status,409)
        self.assertEqual(device.assigned_vlan,11)
        confirmation.assert_not_called()

    def test_register_page_has_no_wrong_vlan_action_or_inline_mismatch_message(self):
        template = (ROOT/'captive-portal/app/templates/register.html').read_text()
        self.assertNotIn('wrongVlanAction', template)
        self.assertIn("window.location.replace(\"{{ url_for('portal.wrong_vlan_page') }}\")", template)
        self.assertIn("const reassignMode = {{ 'true' if reassign_mode else 'false' }};", template)

    def test_wrong_vlan_page_offers_only_one_action_per_state(self):
        template = (ROOT/'captive-portal/app/templates/wrong_vlan.html').read_text()
        self.assertIn('Resend administrator notification', template)
        self.assertIn('I want to use {{ detected_ssid', template)

    def test_pending_wrong_vlan_page_does_not_claim_email_was_sent(self):
        template = (ROOT/'captive-portal/app/templates/wrong_vlan.html').read_text()
        self.assertIn("Network Change Request Pending", template)
        self.assertIn("is already awaiting a decision", template)
        self.assertNotIn("The administrator has been notified", template)

    def test_jinja_templates_parse(self):
        from jinja2 import Environment
        for f in ('admin_firmware.html','register.html','wrong_vlan.html'):
            with self.subTest(f=f):
                Environment().parse((ROOT/'captive-portal/app/templates'/f).read_text())


if __name__=='__main__':
    main()
