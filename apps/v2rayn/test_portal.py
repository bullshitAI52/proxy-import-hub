import base64
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from urllib.request import urlopen
from urllib.error import HTTPError
os.environ['V2N_PUBLIC_URL']='https://example.com/v2rayn'
import server
from export_xui import nodes_from_db

class Tests(unittest.TestCase):
    def test_export_and_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'db'
            with sqlite3.connect(path) as c:
                c.execute('CREATE TABLE inbounds(id INTEGER,port INTEGER,protocol TEXT,enable INTEGER,settings TEXT,stream_settings TEXT)')
                settings=json.dumps({'clients':[{'id':'00000000-0000-4000-8000-000000000001'}]})
                c.execute('INSERT INTO inbounds VALUES (1,1443,?,?,?,?)',('vmess',1,settings,json.dumps({'network':'tcp','security':'tls'})))
            nodes=nodes_from_db(path,[1],'example.com','example.com')
            obj=json.loads(base64.b64decode(nodes[0][8:]))
            self.assertEqual(obj['tls'],'tls');self.assertEqual(obj['sni'],'example.com')
            with self.assertRaises(ValueError):nodes_from_db(path,[2],'example.com','example.com')
    def test_private_routes_and_revocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            server.STATE=Path(tmp)/'state.json'
            token='a'*43
            server.STATE.write_text(json.dumps({'token':token,'nodes':['vmess://example']}))
            http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
            thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
            base='http://127.0.0.1:'+str(http.server_port)
            try:
                with self.assertRaises(HTTPError):urlopen(base+'/wrong/')
                with urlopen(base+'/'+token+'/') as r:self.assertIn('v2rayN',r.read().decode())
                with urlopen(base+'/'+token+'/subscription') as r:
                    self.assertEqual(base64.b64decode(r.read()),b'vmess://example\n')
                    self.assertEqual(r.headers['Cache-Control'],'no-store')
                with urlopen(base+'/'+token+'/nodes') as r:self.assertEqual(r.read(),b'vmess://example\n')
                server.STATE.write_text(json.dumps({'token':'b'*43,'nodes':['vmess://example']}))
                with self.assertRaises(HTTPError):urlopen(base+'/'+token+'/subscription')
            finally:http.shutdown();http.server_close();thread.join()

if __name__=='__main__':unittest.main()
