import base64
import json
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit,parse_qs
import yaml
import test_hub
import server
from subscription_input import node_uri,detect
from client_formats import vless_clash,convert
from resource_limits import Cache,Limiter

NODE={'name':'Reality sample','type':'vless','server':'example.com','port':443,
      'uuid':'12345678-1234-1234-1234-123456789012','tls':True,'network':'tcp',
      'servername':'example.org','client-fingerprint':'chrome','flow':'xtls-rprx-vision',
      'reality-opts':{'public-key':'A'*43,'short-id':'00abcdef'}}

class Features(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        self.c=TestClient(server.app);self.auth={'Authorization':'Bearer test-key'}
        server.CACHE.clear();server.LIMITER.clear()
        with server.db() as con:
            con.execute('DELETE FROM subs');con.execute('DELETE FROM share_meta')
    def create(self,**extra):
        result=self.c.post('/api/shares',headers=self.auth,json={'source':'trojan://test@example.com:443',**extra})
        self.assertEqual(result.status_code,200,result.text)
        return result.json()['url'].rsplit('/',1)[-1],result.json()
    def test_precheck_private_and_no_share(self):
        self.assertEqual(self.c.post('/api/check',json={'source':'x'}).status_code,401)
        result=self.c.post('/api/check',headers=self.auth,json={'source':node_uri(NODE)})
        self.assertEqual(result.status_code,200)
        data=result.json();self.assertEqual(data['count'],1)
        self.assertNotIn(NODE['uuid'],result.text)
        self.assertEqual(data['compatibility']['nodes'][0]['clients']['Surge']['status'],'当前转换链不支持')
        self.assertEqual(data['compatibility']['nodes'][0]['clients']['Clash']['status'],'可生成，待客户端验证')
        self.assertEqual(self.c.get('/api/shares',headers=self.auth).json(),[])
    def test_expiry_all_routes_even_cached(self):
        key,data=self.create(expires_days=7)
        self.assertAlmostEqual(data['expires_at'],time.time()+7*86400,delta=2)
        self.assertEqual(self.c.get('/raw/'+key).status_code,200)
        self.assertEqual(self.c.get('/qr/'+key+'.svg').status_code,200)
        with server.db() as con:con.execute('UPDATE share_meta SET expires_at=? WHERE id=?',(int(time.time())-1,key))
        for path in ['/share/'+key,'/raw/'+key,'/feed/'+key+'/mac.conf','/feed/'+key+'/ios.conf',
                     '/converted/'+key+'/quanx','/converted/'+key+'/clash','/qr/'+key+'.svg']:
            self.assertEqual(self.c.get(path).status_code,410,path)
        self.assertTrue(self.c.get('/api/shares',headers=self.auth).json()[0]['expired'])
        self.assertIsNone(server.CACHE.get((key,'source')))
    def test_permanent_legacy_and_invalid_expiry(self):
        key,data=self.create()
        self.assertIsNone(data['expires_at'])
        with server.db() as con:con.execute('DELETE FROM share_meta WHERE id=?',(key,))
        self.assertEqual(self.c.get('/raw/'+key).status_code,200)
        for days in [-1,1,True,'7',None]:
            self.assertEqual(self.c.post('/api/shares',headers=self.auth,json={'source':'trojan://test@example.com:443','expires_days':days}).status_code,400)
        _,data=self.create(expires_days=30)
        self.assertAlmostEqual(data['expires_at'],time.time()+30*86400,delta=2)
    def test_qr_local_url_and_revoke(self):
        import qrcode
        key,_=self.create()
        with patch.object(qrcode,'make',wraps=qrcode.make) as make:
            result=self.c.get('/qr/'+key+'.svg')
            self.assertEqual(result.status_code,200)
            self.assertIn('<svg',result.text)
            self.assertEqual(make.call_args.args[0],server.core.BASE+'/share/'+key)
            self.assertEqual(result.headers['cache-control'],'no-store')
        self.c.delete('/api/shares/'+key,headers=self.auth)
        self.assertEqual(self.c.get('/qr/'+key+'.svg').status_code,404)
    def test_reality_roundtrip_and_native_clash(self):
        uri=node_uri(NODE);q=parse_qs(urlsplit(uri).query)
        self.assertEqual(q['security'],['reality']);self.assertEqual(q['pbk'],['A'*43])
        self.assertEqual(q['sid'],['00abcdef']);self.assertEqual(q['flow'],['xtls-rprx-vision'])
        recovered=vless_clash(uri)
        self.assertEqual(recovered['reality-opts'],NODE['reality-opts'])
        self.assertEqual(recovered['servername'],NODE['servername'])
        info=detect(yaml.safe_dump({'proxies':[NODE]}).encode())
        self.assertEqual(info['text'].strip(),uri)
        with patch('client_formats.httpx.Client',side_effect=AssertionError('Should not call engine')):
            output=yaml.safe_load(convert(server.core,info['text'],'clash'))
        self.assertEqual(output['proxies'][0]['reality-opts'],NODE['reality-opts'])
        key,_=self.create(source=yaml.safe_dump({'proxies':[NODE]}))
        self.assertEqual(self.c.get('/converted/'+key+'/clash').status_code,200)
    def test_vless_ws_and_rejections(self):
        node={k:v for k,v in NODE.items() if k not in {'reality-opts','flow'}}
        node.update(network='ws',**{'ws-opts':{'path':'/a?b=c','headers':{'Host':'host.example.com'}}})
        recovered=vless_clash(node_uri(node))
        self.assertEqual(recovered['ws-opts'],node['ws-opts'])
        for change in [{'tls':False},{'network':'grpc'},{'reality-opts':{'public-key':'bad'}},
                       {'reality-opts':{'public-key':'A'*43,'short-id':123}},{'flow':'unknown'},{'packet-encoding':'xudp'}]:
            with self.subTest(change=change),self.assertRaises(ValueError):node_uri({**NODE,**change})
        with self.assertRaises(ValueError):vless_clash(node_uri(NODE).split('#')[0]+'&unknown=x')
    def test_cache_and_revocation(self):
        key,_=self.create()
        with patch.object(server.client_formats,'convert',return_value='converted') as mock:
            for _ in range(2):self.assertEqual(self.c.get('/converted/'+key+'/clash').status_code,200)
            self.assertEqual(mock.call_count,1)
            self.c.delete('/api/shares/'+key,headers=self.auth)
            self.assertEqual(self.c.get('/converted/'+key+'/clash').status_code,404)
            self.assertEqual(mock.call_count,1)
    def test_source_check_cache(self):
        with patch.object(server.core,'fetch',return_value=b'trojan://test@example.com:443') as fetch:
            for _ in range(2):self.assertEqual(self.c.post('/api/check',headers=self.auth,json={'source':'https://example.com/sub'}).status_code,200)
            self.assertEqual(fetch.call_count,1)
    def test_cache_bounds_and_ttl(self):
        cache=Cache(ttl=10,max_bytes=6,max_items=2)
        with patch('resource_limits.time.monotonic',return_value=0):
            cache.put(('a',),'123');cache.put(('b',),'456');cache.put(('c',),'789')
            self.assertIsNone(cache.get(('a',)));self.assertEqual(cache.size,6)
        with patch('resource_limits.time.monotonic',return_value=11):self.assertIsNone(cache.get(('c',)))
        cache.put(('huge',),'1234567');self.assertIsNone(cache.get(('huge',)))
    def test_limiter_and_http_429(self):
        limiter=Limiter()
        with patch('resource_limits.time.monotonic',return_value=0):
            self.assertTrue(limiter.allow('a',1));self.assertFalse(limiter.allow('a',1))
        with patch('resource_limits.time.monotonic',return_value=61):self.assertTrue(limiter.allow('a',1))
        for _ in range(20):self.assertEqual(self.c.post('/api/check',json={}).status_code,401)
        response=self.c.post('/api/check',json={})
        self.assertEqual(response.status_code,429);self.assertEqual(response.headers['retry-after'],'60')
    def test_single_conversion_lock(self):
        key,_=self.create()
        server.core.LOCK.acquire()
        try:self.assertEqual(self.c.get('/converted/'+key+'/clash').status_code,429)
        finally:server.core.LOCK.release()

if __name__=='__main__':unittest.main()
