import unittest
from unittest.mock import patch
import yaml
import test_hub
import server
from subscription_groups import resolve

def group(urls):
    return yaml.safe_dump({'proxy-providers':{str(i):{'type':'http','url':url} for i,url in enumerate(urls)}}).encode()

class Groups(unittest.TestCase):
    def setUp(self):
        server.CACHE.clear();server.LIMITER.clear()
        with server.db() as con:
            con.execute('DELETE FROM subs');con.execute('DELETE FROM share_meta')
    def test_merge_dedupe_and_fetch_once(self):
        source=group(['https://example.com/a','https://example.com/b','https://example.com/a'])
        data={'https://example.com/a':b'trojan://test@example.com:443#first',
              'https://example.com/b':b'trojan://test@example.com:443#second\ntrojan://other@example.com:443'}
        with patch.object(server.core,'fetch',side_effect=lambda url:data[url]) as fetch:
            info=server.resolve_input(source)
        self.assertEqual(info['count'],2);self.assertEqual(info['providers'],2)
        self.assertEqual(info['duplicates'],2);self.assertEqual(fetch.call_count,2)
        self.assertIn('#first',info['text']);self.assertNotIn('#second',info['text'])
    def test_fail_closed_and_no_secret_errors(self):
        with patch.object(server.core,'fetch',side_effect=ValueError('private-password')):
            with self.assertRaises(ValueError) as error:server.resolve_input(group(['https://example.com/private-token']))
        self.assertNotIn('private-token',str(error.exception));self.assertNotIn('private-password',str(error.exception))
    def test_cycle_depth_and_limits(self):
        root='https://example.com/root'
        with self.assertRaisesRegex(ValueError,'循环'):resolve(group([root]),lambda url:b'',server.core.validate_url,root_url=root)
        with self.assertRaisesRegex(ValueError,'1–8'):server.resolve_input(group(['https://example.com/'+str(i) for i in range(9)]))
        docs={f'https://example.com/{i}':group([f'https://example.com/{i+1}']) for i in range(4)}
        with self.assertRaisesRegex(ValueError,'嵌套'):resolve(docs['https://example.com/0'],lambda u:docs[u],server.core.validate_url)
    def test_reject_file_http_filter_and_alias(self):
        for provider in [{'type':'file','path':'/etc/passwd'},{'type':'http','url':'http://example.com'},
                         {'type':'http','url':'https://example.com','override':{'password':'x'}}]:
            with self.subTest(provider=provider),self.assertRaises(ValueError):server.resolve_input(yaml.safe_dump({'proxy-providers':{'a':provider}}).encode())
        with self.assertRaisesRegex(ValueError,'锚点'):server.resolve_input(b'proxy-providers: &a {a: *a}')
    def test_pasted_group_refreshes_without_manual_import(self):
        from fastapi.testclient import TestClient
        client=TestClient(server.app);auth={'Authorization':'Bearer test-key'}
        text=group(['https://example.com/a']).decode()
        with patch.object(server.core,'fetch',return_value=b'trojan://one@example.com:443'):
            created=client.post('/api/shares',headers=auth,json={'source':text})
        self.assertEqual(created.status_code,200)
        key=created.json()['url'].rsplit('/',1)[-1]
        with patch.object(server.core,'fetch',return_value=b'trojan://two@example.com:443'):
            self.assertEqual(server.source(key),'trojan://two@example.com:443\n')
        with server.db() as con:secret=con.execute('SELECT secret FROM subs WHERE id=?',(key,)).fetchone()[0]
        self.assertTrue(server.core.CRYPT.decrypt(secret).startswith(b'group:'))
    def test_private_network_and_redirect_protection_retained(self):
        with patch.object(server.core.socket,'getaddrinfo',return_value=[(None,None,None,None,('127.0.0.1',443))]):
            with self.assertRaises(ValueError):server.resolve_input(group(['https://example.com/private']))

if __name__=='__main__':unittest.main()
