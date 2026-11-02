import os,urllib.request,urllib.parse,urllib.error,http.cookies,re,json,subprocess
BASE=os.environ.get('TEST_BASE', 'http://127.0.0.1:18765')
PHP=os.environ['TEST_PHP']
INI=os.environ['TEST_PHP_INI']
PLUGIN=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE=os.environ['TEST_BLUDIT']
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args): return None
opener=urllib.request.build_opener(NoRedirect)
cookies={}
def req(path='/admin/',data=None):
    headers={'User-Agent':'BluditSecureTest','Cookie':'; '.join(k+'='+v for k,v in cookies.items())}
    q=urllib.request.Request(BASE+path,data=urllib.parse.urlencode(data).encode() if data is not None else None,headers=headers)
    try:r=opener.open(q)
    except urllib.error.HTTPError as e:r=e
    for val in r.headers.get_all('Set-Cookie',[]):
        c=http.cookies.SimpleCookie();c.load(val)
        for k,v in c.items():cookies[k]=v.value
    return r.status,r.read().decode(),r.headers

def csrf(body):return re.search(r'name="secureCsrf" value="([^"]+)"',body)[1]
def check(v,label):assert v,label;print('OK',label)
