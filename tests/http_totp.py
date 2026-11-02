from http_helpers import *
s,b,h=req();check('id="jsusername"' in b and 'login-card' in b,'native Bludit login preserved');token=csrf(b)
s,b,h=req('/admin/login?bs=password',{'secureCsrf':'bad','username':'admin','password':'TestPassword123'});check(s==303,'invalid CSRF rejected')
s,b,h=req();token=csrf(b)
native_token=re.search(r'name="tokenCSRF"[^>]*value="([^"]+)"', b)[1]
s,b,h=req('/admin/login',{'tokenCSRF':'invalid','username':'admin','password':'TestPassword123'});check(s==303,'native form rejects invalid CSRF')
s,b,h=req('/admin/login?bs=password',{'secureCsrf':token,'username':'admin','password':'wrong'});check(s==303,'bad password rejected')
s,b,h=req('/admin/login',{'tokenCSRF':native_token,'username':'admin','password':'TestPassword123','remember':'true'});check(s==303 and h['Location'].endswith('/admin/'),'native login form completes on dashboard when MFA disabled')
s,b,h=req('/admin/plugin/pluginbluditsecure');check('Security' in b,'personal security page');token=csrf(b)
check('sidebar col-lg-2' in b and 'bludit.bootstrap.css' in b,'account uses native Bludit admin layout')
check('assets/secure.css' not in b and b.lower().count('<!doctype html>') == 1,'no standalone account theme')
check(re.search(r'assets/secure\.js\?v=[0-9a-f]{16}', b), 'dashboard script URL has a content hash')
check('class="custom-select"' in b and 'btn btn-outline-primary' in b,'account uses Bootstrap controls')
s,legacy,headers=req('/admin/login?bs=account');check(s==303 and '/plugin/pluginbluditsecure' in headers['Location'],'legacy account URL redirects to dashboard page')
s,b,h=req('/admin/login?bs=manage',{'secureCsrf':token,'op':'totp-start'});s,b,h=req('/admin/plugin/pluginbluditsecure');secret=re.search(r'secret=([A-Z2-7]+)',b)[1]
def totp(secret):
    return subprocess.check_output([PHP,'-c',INI,'-r',f'require "{PLUGIN}/src/Totp.php"; echo \\BluditSecure\\Totp::code("{secret}", intdiv(time(),30));']).decode()
code=totp(secret)
s,b,h=req('/admin/login?bs=manage',{'secureCsrf':token,'op':'totp-confirm','code':code});s,b,h=req('/admin/plugin/pluginbluditsecure');check('TOTP is enabled' in b,'TOTP enrollment confirmed')
s,b,h=req('/admin/login?bs=manage',{'secureCsrf':token,'op':'recovery'});s,b,h=req('/admin/plugin/pluginbluditsecure');codes=re.search(r'<pre[^>]*>(.*?)</pre>',b,re.S)[1].splitlines();check(len(codes)==10,'ten recovery codes')
s,b,h=req('/admin/login?bs=logout',{'secureCsrf':token});s,b,h=req();token=csrf(b)
native_token=re.search(r'name="tokenCSRF"[^>]*value="([^"]+)"', b)[1]
s,b,h=req('/admin/login',{'tokenCSRF':native_token,'username':'admin','password':'TestPassword123','remember':'true'});check('bs=mfa' in h['Location'],'native password form only creates pending state')
s,b,h=req('/admin/ajax/dashboard');check(s==401,'pending cannot access AJAX')
s,b,h=req('/admin/');check('Two-step verification' in b,'pending cannot access dashboard');token=csrf(b)
s,b,h=req('/admin/login?bs=mfa',{'secureCsrf':token,'code':code});s,b,h=req('/admin/');check('Two-step verification' in b,'reject already used TOTP')
s,b,h=req('/admin/login?bs=mfa',{'secureCsrf':token,'recovery':codes[0]});check(h['Location'].endswith('/admin/'),'recovery completes MFA on dashboard')
s,b,h=req('/admin/plugin/pluginbluditsecure');check('9 recovery code(s)' in b,'recovery atomically consumed');token=csrf(b)
s,b,h=req('/admin/login?bs=logout',{'secureCsrf':token});s,b,h=req();token=csrf(b)
s,b,h=req('/admin/login?bs=password',{'secureCsrf':token,'username':'admin','password':'TestPassword123'});s,b,h=req('/admin/');token=csrf(b)
s,b,h=req('/admin/login?bs=mfa',{'secureCsrf':token,'recovery':codes[0]});s,b,h=req('/admin/');check('Two-step verification' in b,'recovery replay rejected')
# Direct AJAX without a session must also remain unauthenticated.
cookies.clear();s,b,h=req('/admin/ajax/dashboard');check(s==401,'anonymous AJAX intercepted before native dispatch')
print('Integration checks complete')
