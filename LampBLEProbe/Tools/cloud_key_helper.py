#!/usr/bin/env python3
"""Local CN/owner-only gatt_ltmk retrieval. No passwords or secret logging.

QR/cloud request protocol adapted from PiotrMachowski/Xiaomi-cloud-tokens-extractor
(MIT); see THIRD_PARTY_LICENSES.md. Only the selected lamp's key is exported.
"""
import argparse
import base64
import hashlib
import html
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives.ciphers import Cipher
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import ARC4

MODEL = 'shhf.light.slcwb8'
# The official QR endpoint geolocates this Mac to EU account-login hosts.
# This does not change the selected Xiaomi Home cloud region (always CN).
ALLOWED_HOSTS = {'account.xiaomi.com', 'eu.account.xiaomi.com', 'eu.lp.account.xiaomi.com',
                 'sts.api.io.mi.com', 'api.io.mi.com'}
API_PATHS = {'/v2/homeroom/gethome', '/v2/home/home_device_list', '/v2/blemesh/query_dev'}


class HelperError(Exception):
    pass


def normalize_mac(value):
    clean = re.sub(r'[:-]', '', str(value)).upper()
    if not re.fullmatch(r'[0-9A-F]{12}', clean):
        raise HelperError('设备 MAC 格式不符合预期。')
    return clean


def validate_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in ALLOWED_HOSTS
            or parsed.port not in (None, 443) or parsed.username or parsed.password):
        raise HelperError('登录流程出现未预期的地址，已停止。')
    return url


class CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(request, response, code, message, headers, newurl)


def parse_json(raw):
    if raw.startswith(b'&&&START&&&'):
        raw = raw[len(b'&&&START&&&'):]
    try:
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (ValueError, UnicodeError):
        raise HelperError('服务响应格式不符合预期，未输出响应原文。') from None


def rc4(key, payload):
    cipher = Cipher(ARC4(key), mode=None).encryptor()
    cipher.update(bytes(1024))
    return cipher.update(payload) + cipher.finalize()


def signature(path, params, signed_nonce):
    content = '&'.join(['POST', path] + [f'{k}={v}' for k, v in params.items()] + [signed_nonce])
    return base64.b64encode(hashlib.sha1(content.encode()).digest()).decode()


def encrypt_request(path, payload, ssecurity, nonce):
    signed = base64.b64encode(hashlib.sha256(base64.b64decode(ssecurity) + base64.b64decode(nonce)).digest()).decode()
    params = {'data': json.dumps(payload, separators=(',', ':'))}
    params['rc4_hash__'] = signature(path, params, signed)
    params = {k: base64.b64encode(rc4(base64.b64decode(signed), v.encode())).decode() for k, v in params.items()}
    params['signature'] = signature(path, params, signed)
    params.update(ssecurity=ssecurity, _nonce=nonce)
    return params, base64.b64decode(signed)


def select_device(devices, expected_mac):
    matches = {}
    for item in devices:
        if item.get('model') != MODEL:
            continue
        try:
            mac = normalize_mac(item.get('mac', ''))
        except HelperError:
            continue
        if mac == normalize_mac(expected_mac):
            did = str(item.get('did', ''))
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', did):
                raise HelperError('云端设备标识格式不符合预期。')
            matches[did] = item
    if len(matches) != 1:
        raise HelperError('未唯一匹配到型号和 MAC 均符合的自有灯具，请核对账号及中国大陆地区。')
    return next(iter(matches.values()))


def key_document(response, device, expected_mac):
    if response.get('code') != 0:
        raise HelperError('密钥接口返回错误，错误码：' + str(response.get('code', 'missing'))[:30])
    result = response.get('result')
    key = result.get('gatt_ltmk') if isinstance(result, dict) else None
    if not isinstance(key, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', key):
        raise HelperError('接口未返回有效的 32 字节 gatt_ltmk。不会使用 token 或 beaconkey 替代。')
    mac = normalize_mac(device.get('mac', ''))
    if device.get('model') != MODEL or mac != normalize_mac(expected_mac):
        raise HelperError('导出设备与目标不匹配。')
    return {'format': 'LampBLEProbeKey', 'version': 1, 'region': 'cn',
            'model': MODEL, 'mac': mac, 'gatt_ltmk': key.lower()}


class Cloud:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies), CheckedRedirect())
        self.user_id = None
        self.ssecurity = None
        self.service_token = None
        self.agent = 'LampBLEProbe-local APP/com.xiaomi.mihome APPV/10.5.201'

    def request(self, url, params=None, data=None, headers=None, timeout=15):
        validate_url(url)
        if params:
            url += ('&' if '?' in url else '?') + urllib.parse.urlencode(params)
        request = urllib.request.Request(url, data=data, headers={'User-Agent': self.agent, **(headers or {})})
        try:
            with self.opener.open(request, timeout=timeout) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise HelperError('服务响应过大，已停止。')
                return raw
        except urllib.error.HTTPError as error:
            raise HelperError(f'小米服务返回 HTTP {error.code}，未输出响应原文。') from None
        except (socket.timeout, TimeoutError):
            raise TimeoutError() from None
        except urllib.error.URLError as error:
            if isinstance(error.reason, (socket.timeout, TimeoutError)):
                raise TimeoutError() from None
            raise HelperError('无法安全连接小米服务，请检查网络、代理和系统证书。') from None

    def login(self, show_qr):
        info = parse_json(self.request('https://account.xiaomi.com/longPolling/loginUrl', params={
            '_qrsize': '480', 'qs': '%3Fsid%3Dxiaomiio%26_json%3Dtrue',
            'callback': 'https://sts.api.io.mi.com/sts', '_hasLogo': 'false', 'sid': 'xiaomiio',
            'serviceParam': '', '_locale': 'zh_CN', '_dc': str(int(time.time() * 1000))}))
        try:
            qr_url, poll_url = validate_url(info['qr']), validate_url(info['lp'])
            duration = min(max(int(info['timeout']), 30), 300)
        except (KeyError, ValueError, TypeError):
            raise HelperError('未获得有效登录二维码。') from None
        image = self.request(qr_url)
        if not (image.startswith(b'\x89PNG') or image.startswith(b'\xff\xd8') or image.startswith(b'GIF8')):
            raise HelperError('二维码图片格式不符合预期。')
        show_qr(image)
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            try:
                response = parse_json(self.request(poll_url, timeout=min(10, max(1, deadline-time.monotonic()))))
            except TimeoutError:
                continue
            if all(k in response for k in ('userId', 'ssecurity', 'location')):
                break
            if response.get('code') not in (None, 0):
                raise HelperError('扫码登录未完成或被拒绝，请重新启动工具。')
            time.sleep(1)
        else:
            raise HelperError('二维码已过期，请重新启动工具生成新二维码。')
        user_id = str(response['userId'])
        if not re.fullmatch(r'[0-9]{1,30}', user_id):
            raise HelperError('账号标识格式不符合预期。')
        self.user_id = user_id
        self.ssecurity = response['ssecurity']
        self.request(validate_url(response['location']))
        tokens = [c.value for c in self.cookies if c.name == 'serviceToken' and c.domain.lstrip('.') in {'sts.api.io.mi.com', 'api.io.mi.com', 'io.mi.com', 'mi.com'}]
        if not tokens:
            raise HelperError('登录完成但未取得米家会话，请重新扫码。')
        self.service_token = tokens[-1]

    def api(self, path, payload):
        if path not in API_PATHS:
            raise HelperError('不支持的云端操作。')
        nonce = base64.b64encode(os.urandom(8) + int(time.time()/60).to_bytes(4, 'big')).decode()
        fields, key = encrypt_request(path, payload, self.ssecurity, nonce)
        raw = self.request('https://api.io.mi.com/app' + path, params=fields, data=b'', headers={
            'Accept-Encoding': 'identity', 'Content-Type': 'application/x-www-form-urlencoded',
            'x-xiaomi-protocal-flag-cli': 'PROTOCAL-HTTP2', 'MIOT-ENCRYPT-ALGORITHM': 'ENCRYPT-RC4',
            'Cookie': f'userId={self.user_id}; serviceToken={self.service_token}; yetAnotherServiceToken={self.service_token}; locale=zh_CN; timezone=GMT%2B08%3A00; channel=MI_APP_STORE'})
        if raw.lstrip().startswith(b'{'):
            parsed = parse_json(raw)
        else:
            try:
                parsed = parse_json(rc4(key, base64.b64decode(raw, validate=True)))
            except ValueError:
                raise HelperError('云端加密响应无法解码。') from None
        if parsed.get('code') != 0:
            raise HelperError('云端请求失败，错误码：' + str(parsed.get('code', 'missing'))[:30])
        return parsed

    def retrieve(self, expected_mac):
        homes = self.api('/v2/homeroom/gethome', {'fg': True, 'fetch_share': False,
                         'fetch_share_dev': False, 'limit': 300, 'app_ver': 7})
        devices = []
        homelist = homes.get('result', {}).get('homelist', [])
        if not isinstance(homelist, list) or len(homelist) > 300:
            raise HelperError('家庭列表格式不符合预期。')
        for home in homelist:
            owner = str(home.get('uid', home.get('home_owner', self.user_id)))
            if owner != self.user_id:
                continue
            response = self.api('/v2/home/home_device_list', {'home_owner': int(self.user_id),
                'home_id': int(home['id']), 'limit': 200, 'get_split_device': True, 'support_smart_home': True})
            devices.extend(response.get('result', {}).get('device_info') or [])
        device = select_device(devices, expected_mac)
        result = self.api('/v2/blemesh/query_dev', {'did': str(device['did'])})
        return key_document(result, device, expected_mac)


class LocalUI:
    def __init__(self, expected_mac):
        self.expected_mac = normalize_mac(expected_mac)
        self.lock = threading.Lock()
        self.state = 'starting'
        self.message = '正在连接小米中国大陆服务。'
        self.qr = None
        self.document = None
        self.token = secrets.token_urlsafe(24)
        self.page_path = '/' + secrets.token_urlsafe(24)
        self.closed = threading.Event()

    def update(self, state, message):
        with self.lock:
            self.state, self.message = state, message
        print('STATUS ' + state, flush=True)

    def work(self):
        cloud = None
        try:
            cloud = Cloud()
            def show(image):
                with self.lock:
                    self.qr = image
                self.update('awaiting_scan', '用米家 App 的扫一扫扫描下方二维码，并确认登录。只需本次确认。')
            cloud.login(show)
            with self.lock:
                self.qr = None
            self.update('querying', '已登录，正在匹配自有灯具并查询 gatt_ltmk。')
            document = cloud.retrieve(self.expected_mac)
            with self.lock:
                self.document = json.dumps(document, ensure_ascii=False).encode()
            self.update('ready', '已取得目标灯的密钥。下载密钥文件，通过隔空投送交给 iPhone，再从蓝牙灯诊断导入。不要发到聊天里。')
            cloud.cookies.clear()
            cloud.ssecurity = cloud.service_token = None
        except HelperError as error:
            self.update('error', str(error))
        except TimeoutError:
            self.update('error', '连接超时，请检查网络后重新运行工具。')
        except Exception:
            self.update('error', '处理失败，未输出账号、密钥或服务响应。请只反馈这条状态。')
        finally:
            if cloud is not None:
                cloud.cookies.clear()
                cloud.ssecurity = cloud.service_token = None
            with self.lock:
                self.qr = None
        # Keep success briefly for download; never write sessions or keys to disk.
        self.closed.wait(600)
        self.document = self.qr = None
        self.server.shutdown()

    def handler(self):
        ui = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def send(self, status, content, content_type, disposition=None):
                self.send_response(status)
                self.send_header('Content-Type', content_type)
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('X-Frame-Options', 'DENY')
                self.send_header('Referrer-Policy', 'no-referrer')
                self.send_header('Content-Security-Policy', "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; script-src 'nonce-" + ui.token + "'; connect-src 'self'")
                if disposition:
                    self.send_header('Content-Disposition', disposition)
                self.end_headers()
                self.wfile.write(content)
            def do_GET(self):
                authority = f'127.0.0.1:{self.server.server_port}'
                origin = self.headers.get('Origin')
                if self.headers.get('Host') != authority or (origin and origin != 'http://' + authority):
                    return self.send(403, b'Forbidden', 'text/plain')
                route = urllib.parse.urlsplit(self.path)
                if route.path == ui.page_path:
                    return self.send(200, ui.page().encode(), 'text/html; charset=utf-8')
                if urllib.parse.parse_qs(route.query).get('token') != [ui.token]:
                    return self.send(403, b'Forbidden', 'text/plain')
                with ui.lock:
                    if route.path == '/status':
                        content = json.dumps({'state': ui.state, 'message': ui.message}, ensure_ascii=False).encode()
                        return self.send(200, content, 'application/json; charset=utf-8')
                    if route.path == '/qr' and ui.qr:
                        return self.send(200, ui.qr, 'image/png' if ui.qr.startswith(b'\x89PNG') else 'image/jpeg')
                    if route.path == '/download' and ui.document:
                        return self.send(200, ui.document, 'application/json', 'attachment; filename="LampBLEProbe-key.json"')
                self.send(404, b'Not ready', 'text/plain')
        return Handler

    def page(self):
        return '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>蓝牙灯 · 本地凭证获取</title>
<style>[hidden]{display:none!important}body{font:18px system-ui;max-width:650px;margin:48px auto;padding:20px;line-height:1.6}img{max-width:320px;width:100%}a{display:inline-block;padding:12px 20px;background:#176c53;color:white;border-radius:8px}small{color:#666}</style>
<h1>蓝牙灯 · 本地凭证获取</h1><p>账号地区：中国大陆。仅查询型号 shhf.light.slcwb8 且 MAC 与已诊断灯具匹配的设备。</p>
<p id="status">正在准备二维码…</p><img id="qr" hidden alt="使用米家扫一扫登录"><p><a id="download" hidden>下载本灯密钥文件</a></p>
<small>登录会话与查询结果仅保存在本机内存，工具退出即丢弃。只连接小米官方服务；下载文件包含密钥，请仅导入自己的 iPhone。</small>
<script nonce="TOKEN">const token='TOKEN';let stopped=false; async function tick(){if(stopped)return;try{let s=await(await fetch('/status?token='+token)).json();document.getElementById('status').textContent=s.message;let q=document.getElementById('qr');if(s.state==='awaiting_scan'){if(!q.src)q.src='/qr?token='+token;q.hidden=false}else{q.hidden=true}let a=document.getElementById('download');a.hidden=s.state!=='ready';a.href='/download?token='+token;if(s.state==='ready'||s.state==='error')stopped=true}catch(e){document.getElementById('status').textContent='本地工具已停止，请重新运行。';stopped=true}}tick();setInterval(tick,1500);</script></html>'''.replace('TOKEN', html.escape(self.token))

    def run(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), self.handler())
        self.server.daemon_threads = True
        print(f'OPEN http://127.0.0.1:{self.server.server_port}{self.page_path}', flush=True)
        threading.Thread(target=self.work, daemon=True).start()
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.closed.set()
            self.document = self.qr = None
            self.server.server_close()


def main():
    parser = argparse.ArgumentParser(description='仅在本机为中国大陆自有灯具获取 gatt_ltmk；不接受密码参数。')
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--expected-mac', help='从灯具诊断广播核对的目标 MAC')
    target.add_argument('--target-file', help='只含 expected_mac 的本地目标配置')
    args = parser.parse_args()
    try:
        expected_mac = args.expected_mac
        if args.target_file:
            try:
                with Path(args.target_file).open('rb') as file:
                    config = parse_json(file.read(4097))
                expected_mac = config['expected_mac']
            except (OSError, KeyError, HelperError):
                raise HelperError('无法读取本机目标配置，请使用 --expected-mac 指定已核对的灯具 MAC。') from None
        LocalUI(expected_mac).run()
    except HelperError as error:
        print(str(error))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
