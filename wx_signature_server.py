# -*- coding: utf-8 -*-
"""
方案 B 专用：微信 JS-SDK 签名服务（最小可运行示例，只用 Python 标准库）。

作用：前端页面用当前页 URL 向本服务要一次签名，再调用 wx.config。
      AppSecret 只放在服务端，绝不能写进前端 HTML。

用法：
  1. 填好下面的 APPID / APPSECRET / PORT
  2. 在服务器上运行： python wx_signature_server.py
  3. 用反向代理把它暴露成 https://api.你的域名.com/wx-sign
     （微信官方接口由本服务主动外呼，前端只访问你这一个签名地址）
  4. 自测：浏览器打开
     https://api.你的域名.com/wx-sign?url=https%3A%2F%2Fh5.你的域名.com%2Fwinter2027%2Findex.html
     应返回 {"appId":"wx...","timestamp":"...","nonceStr":"...","signature":"..."}

部署注意（生产环境务必处理）：
  · 当前 Access-Control-Allow-Origin 为 *，上线前改成你的 H5 域名白名单；
  · 加鉴权 / 限流，避免签名接口被外部滥用；
  · access_token 与 jsapi_ticket 有调用频次限制，这里做了 7000 秒内存缓存，
    多实例部署请改成 Redis 等共享缓存；
  · 公众号后台需把本服务器出口 IP 加入「IP 白名单」，否则取 access_token 会失败。
"""
import hashlib
import json
import random
import string
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

# ===== 必填配置 =====
APPID = "wx你的AppID"
APPSECRET = "你的AppSecret"
PORT = 8787
# ====================

_cache = {"ticket": None, "expire": 0.0}


def get_json(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def get_jsapi_ticket():
    """access_token -> jsapi_ticket，两者官方有效期均为 7200 秒，这里缓存 7000 秒。"""
    now = time.time()
    if _cache["ticket"] and now < _cache["expire"]:
        return _cache["ticket"]

    token_url = (
        "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential"
        "&appid=%s&secret=%s" % (APPID, APPSECRET)
    )
    t = get_json(token_url)
    if "access_token" not in t:
        raise RuntimeError("获取 access_token 失败：%s" % t)

    ticket_url = (
        "https://api.weixin.qq.com/cgi-bin/ticket/getticket"
        "?access_token=%s&type=jsapi" % t["access_token"]
    )
    k = get_json(ticket_url)
    if k.get("errcode") != 0 or "ticket" not in k:
        raise RuntimeError("获取 jsapi_ticket 失败：%s" % k)

    _cache["ticket"] = k["ticket"]
    _cache["expire"] = now + 7000
    return k["ticket"]


def make_signature(page_url):
    """按官方规则：字段名字典序拼接后做 SHA1。"""
    ticket = get_jsapi_ticket()
    nonce = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
    ts = str(int(time.time()))
    raw = "jsapi_ticket=%s&noncestr=%s&timestamp=%s&url=%s" % (ticket, nonce, ts, page_url)
    sig = hashlib.sha1(raw.encode("utf-8")).hexdigest()
    return {"appId": APPID, "timestamp": ts, "nonceStr": nonce, "signature": sig}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(200, {})

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path != "/wx-sign":
            self._send(404, {"error": "not found"})
            return
        q = urllib.parse.parse_qs(p.query)
        page_url = q.get("url", [""])[0]
        if not page_url:
            self._send(400, {"error": "missing url"})
            return
        try:
            self._send(200, make_signature(page_url))
        except Exception as e:
            self._send(500, {"error": str(e)})

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))


if __name__ == "__main__":
    if APPID.startswith("wx你的") or APPSECRET.startswith("你的"):
        print("⚠ 请先填写 APPID / APPSECRET 再启动。")
    print("签名服务监听 0.0.0.0:%d ，路径 /wx-sign?url=<当前页面URL>" % PORT)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
