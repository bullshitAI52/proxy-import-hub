import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from cryptography.fernet import Fernet
os.environ['SUB_ADMIN_KEY']='test-only'
os.environ['SUB_PUBLIC_URL']='https://example.com/subscription'
os.environ['SUB_ENCRYPTION_KEY']=Fernet.generate_key().decode()
TMP=tempfile.TemporaryDirectory(dir=os.environ.get('SUB_TEST_ROOT'))
os.environ['SUB_STATE']=TMP.name
import server
from fastapi.testclient import TestClient

class Tests(unittest.TestCase):
    def setUp(self):
        self.client=TestClient(server.app)
        self.headers={'Authorization':'Bearer test-only'}
    def test_denied(self):
        self.assertEqual(self.client.get('/api/subscriptions').status_code,401)
        self.assertEqual(self.client.get('/feed/no/mac.conf').status_code,404)
    def test_urls(self):
        for url in ['http://example.com','file:///etc/passwd','https://a:pass@example.com','https://example.com:8443','https://example.com/#x']:
            with self.assertRaises(ValueError): server.validate_url(url)
    def test_private_ip(self):
        with patch.object(server.socket,'getaddrinfo',return_value=[(0,0,0,'',('127.0.0.1',443))]):
            with self.assertRaises(ValueError): server.public_addresses('example.com')
    def test_create_feed_revoke(self):
        lines=['N001 HK = trojan, example.com, 443, password=test, sni=example.com']
        with patch.object(server,'fetch',return_value=b'input'),patch.object(server,'convert',return_value=lines):
            result=self.client.post('/api/subscriptions',headers=self.headers,json={'url':'https://example.com/secret','name':'test'})
            self.assertEqual(result.status_code,200)
            key=result.json()['id']
            for platform in ['mac','ios']:
                response=self.client.get(f'/feed/{key}/{platform}.conf')
                self.assertEqual(response.status_code,200)
                self.assertIn('#!MANAGED-CONFIG',response.text)
                self.assertNotIn('/secret',response.text)
            raw=(server.STATE/'subscriptions.db').read_bytes()
            self.assertNotIn(b'https://example.com/secret',raw)
            self.client.delete('/api/subscriptions/'+key,headers=self.headers)
            self.assertEqual(self.client.get(f'/feed/{key}/mac.conf').status_code,404)
    @unittest.skipUnless(os.environ.get('SUB_TEST_ENGINE')=='1','requires local subconverter')
    def test_engine_real_fixture(self):
        # Synthetic node, no real credential or server is contacted.
        lines=server.convert(b'trojan://test-password@example.com:443?sni=example.com#Test')
        self.assertEqual(len(lines),1)
        self.assertIn('trojan',lines[0])
    def test_vless_explicit_failure(self):
        import base64
        data=b'vless://test@example.com:443#test'
        for encoded in (data,base64.b64encode(data)):
            with self.assertRaisesRegex(ValueError,'VLESS'):
                server.convert(encoded)

if __name__=='__main__': unittest.main()
