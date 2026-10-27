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
        for marker in ['surgeconfig:///install-config','surge:///install-config','shadowrocket://add/','v2rayN']:
            self.assertIn(marker,page.text)
        self.assertNotIn('<unsafe>',page.text)
        data=self.c.get('/raw/'+key)
        self.assertEqual(base64.b64decode(data.text).decode().strip(),node)
        self.assertEqual(data.headers['Cache-Control'],'no-store')
        with self.assertRaisesRegex(ValueError,'VLESS'):server.core.convert(node.encode())
        self.assertEqual(self.c.delete('/api/shares/'+key,headers=self.auth).status_code,200)
        self.assertEqual(self.c.get('/raw/'+key).status_code,404)
        self.assertEqual(self.c.get('/share/'+key).status_code,404)
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
