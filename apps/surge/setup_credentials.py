"""Run as root: python setup_credentials.py https://your-domain/subscription VPS_IP."""
import os
import secrets
import sys
from pathlib import Path
from urllib.parse import urlsplit
from cryptography.fernet import Fernet
os.umask(0o077)
url=sys.argv[1].rstrip('/') if len(sys.argv)>1 else ''
if urlsplit(url).scheme!='https' or not urlsplit(url).hostname or any(c.isspace() for c in url):
    raise SystemExit('Provide public HTTPS URL')
env=Path('/etc/private-sub.env')
if env.exists(): raise SystemExit('Existing credentials preserved; no changes made')
admin=secrets.token_urlsafe(32)
denied=sys.argv[2] if len(sys.argv)>2 else ''
if '\n' in denied: raise SystemExit('Invalid address')
env.write_text('SUB_PUBLIC_URL='+url+'\nSUB_DENIED_IPS='+denied+'\nSUB_ADMIN_KEY='+admin+'\nSUB_ENCRYPTION_KEY='+Fernet.generate_key().decode()+'\n')
Path('/opt/private-sub/access.txt').write_text('Portal: '+url+'/\nAdmin key: '+admin+'\nKeep private. Never commit.\n')
print('Credentials created. Read /opt/private-sub/access.txt privately.')
