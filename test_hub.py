import base64
import os
import tempfile
import unittest
from unittest.mock import patch
from cryptography.fernet import Fernet
TEMP=tempfile.TemporaryDirectory()
os.environ.update(SUB_STATE=TEMP.name,SUB_PUBLIC_URL='https://example.com/import',SUB_ADMIN_KEY='test-key',SUB_ENCRYPTION_KEY=Fernet.generate_key().decode())
import server
from fastapi.testclient import TestClient

class Tests(unittest.TestCase):
    def setUp(self):self.c=TestClient(server.app);self.auth={'Authorization':'Bearer test-key'}
    def test_private(self):
        self.assertEqual(self.c.get('/api/shares').status_code,401)
        self.assertEqual(self.c.get('/share/missing').status_code,404)
    def test_create_three_clients_revoke(self):
        node='vless://test@example.com:443?security=reality#test'
        r=self.c.post('/api/shares',headers=self.auth,json={'source':node,'name':'<unsafe>'})
        self.assertEqual(r.status_code,200)
        key=r.json()['url'].rsplit('/',1)[-1]
        page=self.c.get('/share/'+key)
        for marker in ['surgeconfig:///install-config','surge:///install-config','shadowrocket://add/','v2rayN','quantumult-x:///add-resource','clash://install-config']:
            self.assertIn(marker,page.text)
        self.assertNotIn('<unsafe>',page.text)
        data=self.c.get('/raw/'+key)
        self.assertEqual(base64.b64decode(data.text).decode().strip(),node)
        self.assertEqual(data.headers['Cache-Control'],'no-store')
        with self.assertRaisesRegex(ValueError,'VLESS'):server.core.convert(node.encode())
        self.assertEqual(self.c.delete('/api/shares/'+key,headers=self.auth).status_code,200)
        self.assertEqual(self.c.get('/raw/'+key).status_code,404)
        self.assertEqual(self.c.get('/share/'+key).status_code,404)
        for target in ('quanx','clash'):
            self.assertEqual(self.c.get('/converted/'+key+'/'+target).status_code,404)
    def test_converted(self):
        r=self.c.post('/api/shares',headers=self.auth,json={'source':'trojan://test@example.com:443#test'})
        key=r.json()['url'].rsplit('/',1)[-1]
        with patch.object(server.client_formats,'convert',return_value='converted') as convert:
            for target in ('quanx','clash'):
                result=self.c.get('/converted/'+key+'/'+target)
                self.assertEqual(result.status_code,200)
                self.assertEqual(result.text,'converted')
                self.assertEqual(convert.call_args.args[2],target)
        with patch.object(server.client_formats,'convert',side_effect=ValueError('private source')):
            result=self.c.get('/converted/'+key+'/clash')
            self.assertEqual(result.status_code,502)
            self.assertNotIn('private source',result.text)
        self.assertEqual(self.c.get('/converted/'+key+'/unknown').status_code,404)
    def test_format_outputs(self):
        from client_formats import validate
        import yaml
        qx='trojan=example.com:443, password=test, tag=Sample'
        self.assertEqual(validate(qx,'quanx'),qx+'\n')
        profile=yaml.safe_load(validate('proxies:\n- {name: DIRECT, type: trojan, server: example.com, port: 443, password: test}\nproxy-providers: {evil: {url: https://example.com}}','clash'))
        self.assertEqual(profile['proxies'][0]['name'],'Node-001')
        self.assertFalse(profile['allow-lan'])
        self.assertNotIn('proxy-providers',profile)
        for bad in ('proxies: []','<html>Error</html>'):
            with self.assertRaises(ValueError):validate(bad,'clash')
        with self.assertRaises(ValueError):validate('error','quanx')
    def test_url_source(self):
        with patch.object(server.core,'fetch',return_value=b'trojan://test@example.com:443#test'):
            r=self.c.post('/api/shares',headers=self.auth,json={'source':'https://example.com/sub'})
            self.assertEqual(r.status_code,200)
        self.assertNotIn(b'https://example.com/sub',(server.core.STATE/'subscriptions.db').read_bytes())
    def test_formats(self):
        text='trojan://test@example.com:443#test'
        self.assertEqual(server.normalize(base64.b64encode(text.encode())).strip(),text)
        for value in [b'proxies: []',b'file:///etc/passwd',b'',b'<html>error</html>']:
            with self.assertRaises(ValueError):server.normalize(value)
    def test_detect_yaml_and_refresh(self):
        from subscription_input import detect
        yaml=b'proxies:\n- {name: Test, type: trojan, server: example.com, port: 443, password: "a@b"}\nrules: [MATCH,DIRECT]'
        info=detect(yaml)
        self.assertEqual(info['format'],'Clash YAML')
        self.assertIn('a%40b@example.com',info['text'])
        self.assertTrue(info['warnings'])
        with patch.object(server.core,'fetch',return_value=yaml):
            response=self.c.post('/api/shares',headers=self.auth,json={'source':'https://example.com/yaml'})
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.json()['format'],'Clash YAML')
            key=response.json()['url'].rsplit('/',1)[-1]
            raw=self.c.get('/raw/'+key)
            self.assertEqual(base64.b64decode(raw.text).decode(),info['text'])
            with patch.object(server.core,'convert',return_value=['N001 = trojan, example.com, 443, password=test']) as conv:
                self.assertEqual(self.c.get('/feed/'+key+'/mac.conf').status_code,200)
                self.assertEqual(conv.call_args.args[0],info['text'].encode())
    def test_detection_boundaries(self):
        from subscription_input import detect
        cases=[b'proxy-providers: {remote: {url: https://example.com}}',
               b'proxies: &a [*a]',b'proxies: !!python/object/apply:os.system [echo]',
               b'proxies: [{type: vless, server: example.com, port: 443}]',
               b'proxies: [{type: ss, server: example.com, port: 443, password: test, cipher: aes-128-gcm, plugin: unknown}]',
               b'[Proxy]\nA = trojan, example.com, 443',b'<html>login</html>']
        for case in cases:
            with self.subTest(case=case),self.assertRaises(ValueError):detect(case)
        info=detect(base64.b64encode(b'trojan://test@example.com:443'))
        self.assertEqual(info['format'],'Base64 节点订阅')
    def test_yaml_ss_vmess(self):
        from subscription_input import detect
        text='proxies:\n- {type: ss, server: "::1", port: 443, cipher: aes-128-gcm, password: test}\n- {type: vmess, server: example.com, port: 443, uuid: 12345678-1234-1234-1234-123456789012, tls: true, network: ws, ws-opts: {path: /socket, headers: {Host: example.com}}}'
        info=detect(text.encode())
        self.assertEqual(info['count'],2)
        lines=info['text'].splitlines()
        self.assertIn('@[::1]:443',lines[0])
        import json
        node=json.loads(base64.b64decode(lines[1][8:]))
        self.assertEqual(node['path'],'/socket')
        self.assertEqual(node['tls'],'tls')

if __name__=='__main__':unittest.main()
