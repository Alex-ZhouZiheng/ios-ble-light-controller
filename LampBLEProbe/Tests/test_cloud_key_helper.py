import base64
import hashlib
import http.client
import importlib.util
import json
import threading
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('cloud_key_helper', Path(__file__).parents[1] / 'Tools/cloud_key_helper.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
MAC = '001122334455'
DEVICE = {'model': h.MODEL, 'mac': MAC, 'did': 'blt.test.device'}
FAKE_KEY = 'ab' * 32  # Synthetic test data, never a user credential.


class HelperTests(unittest.TestCase):
    def test_rc4_rfc6229_at_1024(self):
        self.assertEqual(h.rc4(bytes.fromhex('0102030405'), bytes(16)).hex(), '30abbcc7c20b01609f23ee2d5f6bb7df')

    def test_select_exact_model_and_mac(self):
        self.assertEqual(h.select_device([{'model': 'other'}, DEVICE], '00:11:22:33:44:55'), DEVICE)

    def test_wrong_model_or_missing_mac(self):
        for devices in [[], [{**DEVICE, 'model': 'other'}], [{**DEVICE, 'mac': ''}], [{**DEVICE, 'mac': '112233445566'}]]:
            with self.assertRaises(h.HelperError):
                h.select_device(devices, MAC)

    def test_ambiguous_device_fails(self):
        with self.assertRaises(h.HelperError):
            h.select_device([DEVICE, {**DEVICE, 'did': 'blt.test.second'}], MAC)

    def test_only_gatt_ltmk_exported(self):
        response = {'code': 0, 'result': {'gatt_ltmk': FAKE_KEY, 'token': 'never export', 'beaconkey': 'never export'}}
        document = h.key_document(response, DEVICE, MAC)
        self.assertEqual(set(document), {'format', 'version', 'region', 'model', 'mac', 'gatt_ltmk'})
        self.assertEqual(document['gatt_ltmk'], FAKE_KEY)

    def test_other_key_types_never_used(self):
        for result in [{'token': FAKE_KEY}, {'beaconkey': FAKE_KEY}, {'gatt_ltmk': 'ab'*16}, {'gatt_ltmk': 'z'*64}]:
            with self.assertRaises(h.HelperError):
                h.key_document({'code': 0, 'result': result}, DEVICE, MAC)

    def test_official_hosts_only(self):
        h.validate_url('https://account.xiaomi.com/longPolling/loginUrl')
        h.validate_url('https://eu.lp.account.xiaomi.com/')
        for url in ['http://account.xiaomi.com/', 'https://account.xiaomi.com.evil.test/', 'https://evil.test/',
                    'https://user:password@account.xiaomi.com/', 'https://account.xiaomi.com:444/']:
            with self.assertRaises(h.HelperError):
                h.validate_url(url)

    def test_signature_and_encryption_against_independent_rc4(self):
        # Independent KSA/PRGA checks the connector's cryptography-backed ARC4.
        def reference_rc4(key, value):
            state = list(range(256)); j = 0
            for i in range(256):
                j = (j + state[i] + key[i % len(key)]) % 256
                state[i], state[j] = state[j], state[i]
            i = j = 0; output = bytearray()
            for position, byte in enumerate(bytes(1024) + value):
                i = (i + 1) % 256; j = (j + state[i]) % 256
                state[i], state[j] = state[j], state[i]
                mixed = byte ^ state[(state[i]+state[j]) % 256]
                if position >= 1024: output.append(mixed)
            return bytes(output)
        sec = base64.b64encode(bytes(range(32))).decode()
        nonce = base64.b64encode(bytes(range(12))).decode()
        fields, key = h.encrypt_request('/v2/blemesh/query_dev', {'did': DEVICE['did']}, sec, nonce)
        signed = base64.b64encode(key).decode()
        data = json.dumps({'did': DEVICE['did']}, separators=(',', ':'))
        preimage = f'POST&/v2/blemesh/query_dev&data={data}&{signed}'.encode()
        digest = base64.b64encode(hashlib.sha1(preimage).digest())
        self.assertEqual(base64.b64decode(fields['data']), reference_rc4(key, data.encode()))
        self.assertEqual(base64.b64decode(fields['rc4_hash__']), reference_rc4(key, digest))
        self.assertEqual(fields['ssecurity'], sec)

    def test_only_owner_homes_queried(self):
        class FakeCloud(h.Cloud):
            user_id = '123'
            def __init__(self): self.calls = []
            def api(self, path, payload):
                self.calls.append((path, payload))
                if path.endswith('gethome'):
                    return {'code': 0, 'result': {'homelist': [{'id': 1, 'uid': 123}, {'id': 2, 'uid': 999}]}}
                if path.endswith('home_device_list'):
                    return {'code': 0, 'result': {'device_info': [DEVICE]}}
                return {'code': 0, 'result': {'gatt_ltmk': FAKE_KEY}}
        cloud = FakeCloud()
        self.assertEqual(cloud.retrieve(MAC)['gatt_ltmk'], FAKE_KEY)
        self.assertEqual([x[1]['home_id'] for x in cloud.calls if x[0].endswith('home_device_list')], [1])
        self.assertEqual(cloud.calls[-1], ('/v2/blemesh/query_dev', {'did': DEVICE['did']}))

    def test_no_control_endpoint(self):
        cloud = h.Cloud()
        with self.assertRaises(h.HelperError):
            cloud.api('/miotspec/prop/set', {'value': True})

    def test_browser_surface_no_key_and_no_foreign_origin(self):
        ui = h.LocalUI(MAC)
        ui.state = 'ready'
        ui.document = json.dumps(h.key_document({'code': 0, 'result': {'gatt_ltmk': FAKE_KEY}}, DEVICE, MAC)).encode()
        server = h.ThreadingHTTPServer(('127.0.0.1', 0), ui.handler())
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
        try:
            connection.request('GET', ui.page_path)
            response = connection.getresponse(); page = response.read()
            self.assertEqual(response.status, 200); self.assertNotIn(FAKE_KEY.encode(), page)
            connection.request('GET', '/status?token=' + ui.token)
            response = connection.getresponse(); status = response.read()
            self.assertNotIn(FAKE_KEY.encode(), status)
            connection.request('GET', '/download')
            response = connection.getresponse(); response.read(); self.assertEqual(response.status, 403)
            connection.request('GET', '/download?token=' + ui.token, headers={'Origin': 'https://foreign.example'})
            response = connection.getresponse(); response.read(); self.assertEqual(response.status, 403)
            connection.request('GET', '/download?token=' + ui.token)
            response = connection.getresponse(); content = response.read()
            self.assertEqual(json.loads(content)['gatt_ltmk'], FAKE_KEY)
            self.assertEqual(response.getheader('Cache-Control'), 'no-store')
        finally:
            connection.close(); server.shutdown(); server.server_close()


if __name__ == '__main__':
    unittest.main()
