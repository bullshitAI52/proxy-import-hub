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

if __name__=='__main__':unittest.main()
