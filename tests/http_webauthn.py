from http_helpers import *
import base64,hashlib,struct,pathlib
# Reset only the disposable plugin fixture.
for p in (pathlib.Path(FIXTURE)/'bl-content/databases/plugins/bludit-secure').glob('secure.*.php'):p.unlink()
PHP_CMD=[PHP,'-c',INI]
b64=lambda x:base64.urlsafe_b64encode(x).decode().rstrip('=')
def cbor(x):
 def head(major,n):
  return bytes([major*32+n]) if n<24 else bytes([major*32+24,n]) if n<256 else bytes([major*32+25])+struct.pack('>H',n)
 if isinstance(x,int):return head(0,x) if x>=0 else head(1,-x-1)
 if isinstance(x,bytes):return head(2,len(x))+x
 if isinstance(x,str):return head(3,len(x.encode()))+x.encode()
 if isinstance(x,dict):return head(5,len(x))+b''.join(cbor(k)+cbor(v) for k,v in x.items())
keyfile=str(pathlib.Path(FIXTURE)/'test-key.pem')
raw=subprocess.check_output(PHP_CMD+['-r',f'$k=openssl_pkey_new(["private_key_type"=>OPENSSL_KEYTYPE_EC,"curve_name"=>"prime256v1"]);openssl_pkey_export($k,$pem);file_put_contents("{keyfile}",$pem);$d=openssl_pkey_get_details($k);echo json_encode([base64_encode($d["ec"]["x"]),base64_encode($d["ec"]["y"])]);'])
x,y=map(base64.b64decode,json.loads(raw))
s,b,h=req();token=csrf(b)
s,b,h=req('/admin/login?bs=password',{'secureCsrf':token,'username':'admin','password':'TestPassword123'});s,b,h=req('/admin/login?bs=account');token=csrf(b)
def post(action,**fields):return req('/admin/login?bs='+action,{'secureCsrf':token,**fields})
s,b,h=post('key-create-options');options=json.loads(b);check(s==200,'registration options')
cred=b'bludit-test-key-1';rp=hashlib.sha256(b'127.0.0.1').digest()
auth=rp+b'\x45'+struct.pack('>I',0)+b'\0'*16+struct.pack('>H',len(cred))+cred+cbor({1:2,3:-7,-1:1,-2:x,-3:y})
client=json.dumps({'type':'webauthn.create','challenge':options['publicKey']['challenge'],'origin':'https://127.0.0.1:18765'}).encode()
s,b,h=post('key-create-finish',clientDataJSON=b64(client),attestationObject=b64(cbor({'fmt':'none','attStmt':{},'authData':auth})),label='Test passkey');check(s==200,'signed registration accepted')
s,b,h=req('/admin/login?bs=account');check('Test passkey' in b,'registered passkey listed');token=csrf(b)
post('logout');s,b,h=req();token=csrf(b);post('password',username='admin',password='TestPassword123');s,b,h=req('/admin/');token=csrf(b);check('Vérification en deux étapes' in b,'passkey enabled as second factor')
def assertion(origin,valid=True):
 s,b,h=post('key-get-options');check(s==200,'assertion options');opts=json.loads(b)
 client=json.dumps({'type':'webauthn.get','challenge':opts['publicKey']['challenge'],'origin':origin}).encode()
 auth=rp+b'\x05'+struct.pack('>I',1)
 msg=auth+hashlib.sha256(client).digest()
 signature=subprocess.check_output(['openssl','dgst','-sha256','-sign',keyfile],input=msg)
 return post('key-get-finish',id=b64(cred),clientDataJSON=b64(client),authenticatorData=b64(auth),signature=b64(signature if valid else b'bad'))
s,b,h=assertion('https://evil.example');check(s==400,'wrong origin rejected')
s,b,h=assertion('https://127.0.0.1:18765',False);check(s==400,'bad signature rejected')
s,b,h=assertion('https://127.0.0.1:18765');check(s==200 and 'redirect' in json.loads(b),'valid signed assertion completes MFA')
s,b,h=req('/admin/login?bs=account');check('Sécurité de mon compte' in b,'WebAuthn authenticated session')
# A finish request cannot reuse a consumed challenge.
s,b,h=post('key-get-finish',id=b64(cred));check(s==400,'consumed challenge rejected')
print('WebAuthn integration checks complete')
