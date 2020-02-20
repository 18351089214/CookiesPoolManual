# -*- coding: utf-8 -*-

import base64
import binascii
import json
import math
import random
import re
import time
import json
from urllib.parse import quote
from urllib.parse import urlencode

import requests
import rsa
from db import RedisClient


class WeiboCookies(object):
    requests.packages.urllib3.disable_warnings()

    # 类初始化
    def __init__(self, username, password):
        super(WeiboCookies, self).__init__()
        self.s = requests.Session()
        self.username = username
        self.password = password
        self.servertime = None
        self.pcid = None
        self.nonce = None
        self.pubkey = None
        self.rsakv = None
        self.userid = None
        self.userid = None

    # 返回一个随机的请求头 headers
    def get_headers(self):
        user_agent_list = [
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.163 Safari/535.1',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0) Gecko/20100101 Firefox/6.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36'
        ]
        UserAgent = random.choice(user_agent_list)
        headers = {'User-Agent': UserAgent}
        return headers

    # 用户名加密
    def user_encrypt(self):
        user = quote(self.username)
        user = base64.b64encode(user.encode())
        return str(user, encoding='utf-8')

    def prelogin(self):
        params = {
            'entry': 'weibo',
            'callback': 'sinaSSOController.preloginCallBack',
            'su': self.user_encrypt(),
            'rsakt': 'mod',
            'checkpin': 1,
            'client': 'ssologin.js(v1.4.19)',
            '_': str(int(time.time()) * 1000)
        }

        try:
            url = 'https://login.sina.com.cn/sso/prelogin.php?' + urlencode(params)
            response = self.s.get(url=url, headers=self.get_headers(), verify=False)
            if response.status_code == 200:
                resp = response.text
                begPos = resp.find('{')
                endPos = resp.find('}')
                resp = resp[begPos:endPos + 1]
                resp = json.loads(resp)
                self.pcid = resp['pcid']
                self.servertime = resp['servertime']
                self.nonce = resp['nonce']
                self.pubkey = resp['pubkey']
                self.rsakv = resp['rsakv']
        except requests.exceptions.ConnectionError as e:
            print(e.args)

    def get_qrcode(self):
        # 输入生成的验证码
        params = {
            'r': math.floor(random.random() * math.pow(10, 8)),
            's': 0,
            'p': self.pcid
        }
        url = 'https://login.sina.com.cn/cgi/pin.php?'
        resp = self.s.get(url=url, headers=self.get_headers(), params=params, verify=False)
        with open('qrcode.png', 'wb') as fp:
            fp.write(resp.content)
        qrcode = input('Please input verifycode: ')
        # chaojiying = Chaojiying_Client('18351089214', 'liusha4439', '901676')  # 用户中心>>软件ID 生成一个替换 96001
        # dataJson = chaojiying.PostPic(resp.content, 1902)  # 1902 验证码类型  官方网站>>价格体系 3.4+版 print 后要加()
        # qrcode = dataJson['pic_str']
        return qrcode

    # 对密码加密
    def encry_password(self):
        rsaPublickey = int(self.pubkey, 16)
        key = rsa.PublicKey(rsaPublickey, 65537)  # 创建公钥
        message = str(self.servertime) + '\t' + str(self.nonce) + '\n' + str(self.password)  # 拼接明文js加密文件中得到
        message = bytes(message, encoding="utf-8")
        passwd = rsa.encrypt(message, key)  # 加密
        passwd = binascii.b2a_hex(passwd)  # 将加密信息转换为16进制。
        return passwd

    def get_replace_url(self, response):
        if response:
            pattern = re.compile('.*location.replace\(\"(.*?)\"\).*')
            result = re.search(pattern, response)
            return result.group(1)

    def get_ticket_url(self, response):
        if response:
            pattern = re.compile('.*location.replace\(\'(.*?)\'\).*')
            result = re.search(pattern, response)
            return result.group(1)

    def get_response(self, url):
        try:
            response = self.s.get(url=url, headers=self.get_headers(), verify=False)
            if response.status_code == 200 or response.status_code == 302:
                return response.text

            return None
        except:
            return None

    def get_redirect(self, response):
        if response:
            pattern = re.compile('\"uniqueid\":\"(\d+)\".*')
            result = re.search(pattern, response)
            url = r'https://weibo.com/u/' + result.group(1) + "/home"
            return url

    def get_userid(self, response):
        if response:
            beg_pos = response.find("$CONFIG['uid']")
            if beg_pos != -1:
                beg_pos += len("$CONFIG['uid']='")
            end_pos = response.find("$CONFIG['nick']")
            result = response[beg_pos:(end_pos - 2)]

    def main(self):
        url = 'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)'
        self.prelogin()
        door = self.get_qrcode()
        params = {
            'entry': 'weibo',
            'gateway': 1,
            'from': '',
            'savestate': 7,
            'qrcode_flag': False,
            'useticket': 1,
            'pagerefer': 'https://passport.weibo.com/visitor/visitor?entry=miniblog&a=enter&url=https%3A%2F%2Fweibo.com%2F&domain=.weibo.com&ua=php-sso_sdk_client-0.6.28&_rand=1566560955.9263',
            'pcid': self.pcid,
            'door': door,
            'vsnf': 1,
            'su': self.user_encrypt(),
            'service': 'miniblog',
            'servertime': self.servertime,
            'nonce': self.nonce,
            'pwencode': 'rsa2',
            'rsakv': self.rsakv,
            'sp': self.encry_password(),
            'encoding': 'UTF-8',
            'prelt': random.randint(100, 500),
            'url': 'https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'
        }

        try:
            response = self.s.post(url=url, headers=self.get_headers(), params=urlencode(params),
                                   verify=False)
            if response.status_code == 200:
                replace_url = self.get_replace_url(response.text)
                ticke_response = self.get_response(replace_url)
                ticket_url = self.get_ticket_url(ticke_response)
                redirect_response = self.get_response(ticket_url)
                redirect_url = self.get_redirect(redirect_response)
                result_response = self.get_response(redirect_url)
                print('Login Succeeded!')
                return {
                    'status': 1,
                    'type': 'weibo',
                    'content': requests.utils.dict_from_cookiejar(self.s.cookies)
                }
        except:
            print('Login Failed!')
        print('Leave login')
        return {
            'status': 3,
            'type': 'weibo',
            'content': '登录失败'
        }


if __name__ == '__main__':
    conn = RedisClient('cookies', 'weibo')
    while True:
        num = input('Please input your number: ')
        num = int(num)
        if num == 0:
            print('程序终止！')
            break
        if num == 1:
            result = WeiboCookies('andrew_wf@sina.cn', 'WF#zero034439').main()
            if result['status'] == 1:
                cookie = json.dumps(eval(str(result['content']).replace('\'', '\"')))
                print('andrew_wf@sina.cn cookie: \n')
                print(cookie)
                conn.set('andrew_wf@sina.cn', cookie)
            if result['status'] == 3:
                print(result['content'])
        if num == 2:
            result = WeiboCookies('290868461@qq.com', 'liusha4439').main()
            if result['status'] == 1:
                cookie = json.dumps(eval(str(result['content']).replace('\'', '\"')))
                print('290868461@qq.com cookie: \n')
                print(cookie)
                conn.set('290868461@qq.com', cookie)
            if result['status'] == 3:
                print(result['content'])

        if num == 3:
            result = WeiboCookies('2337956208@qq.com', 'liusha4439').main()
            if result['status'] == 1:
                cookie = json.dumps(eval(str(result['content']).replace('\'', '\"')))
                print('2337956208@qq.com cookie: \n')
                print(cookie)
                conn.set('2337956208@qq.com', cookie)
            if result['status'] == 3:
                print(result['content'])
