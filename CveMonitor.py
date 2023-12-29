#coding=utf-8

import requests
import re
import time
import smtplib
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import datetime
from email import encoders
import base64
import random
import json
from hashlib import md5
from bs4 import BeautifulSoup


class CVE(object):
    def __init__(self):
        self.headres={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36'}
        self.open=open("CVE.html","w+")
        self.sum = 0
        self.WiH = ['CRITICAL','HIGH','MEDIUM','LOW']
    def cve_scan(self):
        url="https://cassandra.cerias.purdue.edu/CVE_changes/today.html"
        urlscan=requests.get(url,headers=self.headres,verify=False)
        cve_re=re.compile(r"<A HREF = '(.+?)'>(.+?)</A>(.*)+?<br />")   #若只想爬今日上新的CVE去掉(.*)+?即可
        re_cve=re.findall(cve_re,urlscan.text)
        self.open.write('<!DOCTYPE html><html><meta charset="utf-8"><title>最新漏洞情报</title><head><style type="text/css">table.hovertable { font-family: verdana,arial,sans-serif; font-size:11px; color:#333333; border-width: 1px; border-color: #999999; border-collapse: collapse; display: flex; justify-content: center; /* 水平居中 */ align-items: center; /* 垂直居中 */ margin: 10px;} table.hovertable th { background-color:#e1e0f3; border-width: 1px; padding: 8px; border-style: solid; border-color: #a9c6c9; width: 130px; } table.hovertable tr { background-color:#ebe7f0; } table.hovertable td { border-width: 1px; padding: 8px; border-style: solid; border-color: #a9c6c9; text-align: center; } #Description{ width: 330px; }</style></head><body><table class="hovertable"><tr><th>漏洞编号</th><th id="Description">漏洞描述</th><th>漏洞评分</th><th>参考链接</th></tr>')
        for cve in re_cve:
            print ("CVE-"+cve[1])
            urlcve=requests.get(cve[0],headers=self.headres,verify=False)
            recve=re.compile(r'<tr>.+?<th colspan="2">Description</th>.+?</tr>.+?<tr>.+?<td colspan="2">(.+?)</td>.+?</tr>',re.DOTALL)
            cvere=re.findall(recve,urlcve.text)

            
            #新增漏洞危害
            url2="https://nvd.nist.gov/vuln/detail/CVE-"+cve[1]
            urlcve2=requests.get(url2,headers=self.headres,verify=False)
            # 使用BeautifulSoup解析HTML源码  
            soup = BeautifulSoup(urlcve2.text, 'html.parser')  
            # 提取特定元素的值  
            my_div = soup.find('a', {'id': 'Cvss3NistCalculatorAnchor'})  # 查找id为"Cvss3NistCalculatorAnchor"的a元素   
            if my_div:
                if self.WiH[0] in my_div.text:
                    WeiHai = '严重'
                elif self.WiH[1] in my_div.text:
                    WeiHai = '高危'
                elif self.WiH[2] in my_div.text:
                    WeiHai = '中危'
                else:
                    WeiHai = '低危'
            else:
                WeiHai = '暂无评分'


            for cvecve in cvere:
                cvecve = BaiduTrans(cvecve)    #百度翻译，不想翻译直接将此行注释掉即可
                #self.open.write("<style>a{text-decoration: none;}</style>CVE-ID：<a href="+cve[0]+" target='_blank'>CVE-"+cve[1]+"</a><p>描述："+cvecve+"</p></br>")
                self.open.write("<tr onmouseover=\"this.style.backgroundColor=\'#ffff66\';\" onmouseout=\"this.style.backgroundColor=\'#ebe7f0\';\"><td>CVE-"+cve[1]+"</td><td>"+cvecve+"</td><td>"+WeiHai+"</td><td><a href="+cve[0]+" target=\'_blank\'>CVE-"+cve[1]+"</a></td></tr>")
                self.open.flush()
                self.sum+=1
                print(cvecve)
        self.open.write("</table></body></html>")
    def email(self):
        mail_content = "<div>最新CVE漏洞情报</div>"
        # 发送邮箱服务器
        smtp_server = 'smtp.exmail.qq.com'

        # 发送邮箱用户名和密码
        user = ''
        password = ''  # 设置的邮件服务独立密码

        # 发送和接收邮箱
        sender = ''

        # 用户甲，用户乙...
        receives = ['','','']
        subject = "最新漏洞预警【今日份新增"+str(self.sum)+"个漏洞】"
        f_f=open("CVE.html",'r+')
        f_ff=f_f.read()
        if len(f_ff)==0:
            pass
        if len(f_ff)>0:
            print (f_ff)
            msg = MIMEMultipart()
            msg.attach(MIMEText(f_ff,_subtype='html',_charset='utf-8'))
            msg['subject'] = Header(subject, 'utf-8')
            msg['From'] = sender
            msg['To'] = ','.join(receives)

            #添加附件
            today_time = datetime.datetime.now().date()
            with open('CVE.html', "rb") as html_attachment:
                html_part = MIMEApplication(html_attachment.read(), Name='CVE.html')
            html_part['Content-Disposition'] = f'attachment; filename=str(today_time) +"最新漏洞情报.html"'
            msg.attach(html_part)

            try:
                # SSl协议端口号要使用465
                smtp = smtplib.SMTP_SSL(smtp_server, 465)

                # HELO向服务器标识用户的身份
                smtp.helo(smtp_server)

                # EHLO 服务器返回结果确认
                smtp.ehlo(smtp_server)

                # 登录邮箱服务器用户名和密码
                smtp.login(user, password)
                smtp.sendmail(sender, receives, msg.as_string())
                smtp.quit()
                print ("Success!")
            except:
                print ("Falied")


def BaiduTrans(cvecve):
    appid = ''  #百度翻译APPid
    appkey = '' #百度翻译appkey
    from_lang = 'en'
    to_lang = 'zh'
    endpoint = 'http://api.fanyi.baidu.com'
    path = '/api/trans/vip/translate'
    url = endpoint + path
    query = cvecve
    salt = random.randint(32768, 65536)
    sign = make_md5(appid + query + str(salt) + appkey)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = {'appid': appid, 'q': query, 'from': from_lang, 'to': to_lang, 'salt': salt, 'sign': sign}
    r = requests.post(url, params=payload, headers=headers)
    result = r.json()
    print(json.dumps(result, indent=4, ensure_ascii=False))
    cvecve = result['trans_result'][0]['dst']
    return cvecve

def make_md5(s, encoding='utf-8'):
    return md5(s.encode(encoding)).hexdigest()


if __name__ == '__main__':
    CVESCAN=CVE()
    CVESCAN.cve_scan()
    CVESCAN.email()
