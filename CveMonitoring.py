#coding=utf-8

import requests
import re
import time
import smtplib
import smtplib  # 发邮件的模块
from email.mime.text import MIMEText  # 定义邮件内容
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication  #用于添加附件
#import logging
import datetime
from email import encoders
import base64
import random
import json
from hashlib import md5
from bs4 import BeautifulSoup
import urllib3
import sqlite3


class CVE(object):
    def __init__(self):
        self.headres={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36'}
        self.open=open("CVE.html","w+")
        self.sum = 0
        self.WiH = ['CRITICAL','HIGH','MEDIUM','LOW']
        self.CuData = datetime.date.today()


    def cve_scan(self):
        url="https://cassandra.cerias.purdue.edu/CVE_changes/today.html"
        urlscan=requests.get(url,headers=self.headres,verify=False)
        cve_re=re.compile(r"<A HREF = '(.+?)'>(.+?)</A>(.*)+?<br />")
        re_cve=re.findall(cve_re,urlscan.text)
        self.open.write('<!DOCTYPE html><html><meta charset="utf-8"><title>最新漏洞情报</title><head><style type="text/css">table.hovertable { font-family: verdana,arial,sans-serif; font-size:11px; color:#333333; border-width: 1px; border-color: #999999; border-collapse: collapse; display: flex; justify-content: center; /* 水平居中 */ align-items: center; /* 垂直居中 */ margin: 10px;} table.hovertable th { background-color:#e1e0f3; border-width: 1px; padding: 8px; border-style: solid; border-color: #a9c6c9; width: 130px; } table.hovertable tr { background-color:#ebe7f0; } table.hovertable td { border-width: 1px; padding: 8px; border-style: solid; border-color: #a9c6c9; text-align: center; } #Description{ width: 330px; }</style></head><body><table class="hovertable"><tr><th>漏洞编号</th><th id="Description">漏洞描述</th><th>漏洞评分</th><th>漏洞类型</th><th>参考链接</th></tr>')
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
                WeiHai = 'N/A'

            for cvecve in cvere:
                cvecve = BaiduTrans(cvecve)    #百度翻译
                #self.open.write("<style>a{text-decoration: none;}</style>CVE-ID：<a href="+cve[0]+" target='_blank'>CVE-"+cve[1]+"</a><p>描述："+cvecve+"</p></br>")
                self.open.write("<tr onmouseover=\"this.style.backgroundColor=\'#ffff66\';\" onmouseout=\"this.style.backgroundColor=\'#ebe7f0\';\"><td>CVE-"+cve[1]+"</td><td>"+cvecve+"</td><td>"+WeiHai+"</td><td>未定义</td><td><a href="+cve[0]+" target=\'_blank\'>CVE-"+cve[1]+"</a></td></tr>")
                self.open.flush()
                self.sum+=1
                DataStorage("CVE","CVE-"+cve[1],cvecve,my_div.text,"N/A",self.CuData,cve[0])
                print(cvecve)
        #self.open.write("</table></body></html>")


    def AliVul_scan(self):
        url = "https://avd.aliyun.com/nvd/list?page=1"
        urlscan = requests.get(url, headers=self.headres, verify=False)
        recve = re.compile(
            '<tr>.*?target="_blank">(.*?)</a></td>.*?<td>(.*?)</td>.*?<button.*?>(.*?)</button>.*?nowrap="nowrap">(.*?)</td>' +
            '.*?<button.*?>(.*?)</button>.*?</tr>', re.DOTALL)
        contents = re.findall(recve, urlscan.text)
        # print(contents)
        for content in contents:
            """yield {
                'cve_id': content[0].strip(),
                'vul_name': content[1],
                'cul_type': content[2].strip(),
                'cve_date': content[-2].strip(),
                'cvs_level': content[-1].strip()
            }"""
            date_str = content[-2].strip()
            date = datetime.datetime.strptime(date_str, "%Y-%m-%d")
            if date.date() == self.CuData:
                self.open.write(
                    "<tr onmouseover=\"this.style.backgroundColor=\'#ffff66\';\" onmouseout=\"this.style.backgroundColor=\'#ebe7f0\';\"><td>" +
                    content[0].strip() + "</td><td>" + content[1] + "</td><td>" + content[-1].strip() + "</td><td>" + content[2].strip() + "</td><td><a href=https://avd.aliyun.com/nvd/list target=\'_blank\'>搜索CVE编号获取更多漏洞信息</a></td></tr>")
                self.open.flush()
                self.sum += 1
                link = 'https://avd.aliyun.com/nvd/list'
                DataStorage("AliCVE", content[0].strip(), content[1], content[-1].strip(), content[2].strip(), content[-2].strip(), link)
                print(content[1])

        url = "https://avd.aliyun.com/nonvd/list?page=1"
        urlscan = requests.get(url, headers=self.headres, verify=False)
        recve = re.compile(
            '<tr>.*?target="_blank">(.*?)</a></td>.*?<td>(.*?)</td>.*?<button.*?>(.*?)</button>.*?nowrap="nowrap">(.*?)</td>' +
            '.*?<button.*?>(.*?)</button>.*?</tr>', re.DOTALL)
        contents = re.findall(recve, urlscan.text)
        # print(contents)
        for content in contents:
            """yield {
                'cve_id': content[0].strip(),
                'vul_name': content[1],
                'cul_type': content[2].strip(),
                'cve_date': content[-2].strip(),
                'cvs_level': content[-1].strip()
            }"""
            date_str = content[-2].strip()
            date = datetime.datetime.strptime(date_str, "%Y-%m-%d")
            if date.date() == self.CuData:
                self.open.write(
                    "<tr onmouseover=\"this.style.backgroundColor=\'#ffff66\';\" onmouseout=\"this.style.backgroundColor=\'#ebe7f0\';\"><td>" +
                    content[0].strip() + "</td><td>" + content[1] + "</td><td>" + content[-1].strip() + "</td><td>" +
                    content[
                        2].strip() + "</td><td><a href=https://avd.aliyun.com/nonvd/list?page=1 target=\'_blank\'>搜索AVD编号获取更多漏洞信息</a></td></tr>")
                self.open.flush()
                self.sum += 1
                link = 'https://avd.aliyun.com/nonvd/list'
                DataStorage("AVD", content[0].strip(), content[1], content[-1].strip(), content[2].strip(), content[-2].strip(), link)
                print(content[1])
        self.open.write("</table></body></html>")


    def email(self):
        mail_content = "<div>最新漏洞情报</div>"
        # 发送邮箱服务器
        smtp_server = 'smtp.exmail.qq.com'

        # 发送邮箱用户名和密码
        user = ''
        password = ''  # 设置的邮件服务独立密码

        # 发送和接收邮箱
        sender = ''

        # 用户甲，用户乙...
        receives = ['','']
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
    appid = ''
    appkey = ''
    # For list of language codes, please refer to `https://api.fanyi.baidu.com/doc/21`
    from_lang = 'en'
    to_lang = 'zh'
    endpoint = 'http://api.fanyi.baidu.com'
    path = '/api/trans/vip/translate'
    url = endpoint + path
    query = cvecve
    salt = random.randint(32768, 65536)
    sign = make_md5(appid + query + str(salt) + appkey)
    # Build request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = {'appid': appid, 'q': query, 'from': from_lang, 'to': to_lang, 'salt': salt, 'sign': sign}
    # Send request
    r = requests.post(url, params=payload, headers=headers)
    result = r.json()
    # Show response
    print(json.dumps(result, indent=4, ensure_ascii=False))
    # Extract and print the 'dst' translation result
    cvecve = result['trans_result'][0]['dst']
    return cvecve

def make_md5(s, encoding='utf-8'):
    return md5(s.encode(encoding)).hexdigest()

#数据库存储
def DataStorage(Tab,ID,Dic,level,type,CuData,link):
    # 连接到SQLite数据库（如果不存在则创建）
    conn = sqlite3.connect('Vuln.db')
    # 创建一个游标对象
    cur = conn.cursor()
    # 检查表是否存在
    def check_table(table_name):
        cursor = conn.cursor()
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
        if cursor.fetchone() is None:
            return False
        return True
        # 定义要存储的数据
    data = [(ID, Dic, level, type, CuData, link)]
    # 检查并创建表
    if not check_table(Tab):
        qurey = "CREATE TABLE " + Tab + "(ID TEXT, DIC TEXT, level FLOAT, type TEXT, CuData TEXT, link TEXT)"
        cur.execute(qurey)

        # 插入数据到表中

    cur.executemany("INSERT INTO "+ Tab +"(ID, DIC, level, type, CuData, link) VALUES (?, ?, ?, ?, ?, ?)", data)
    # 提交事务
    conn.commit()
    # 关闭连接
    conn.close()


if __name__ == '__main__':
    urllib3.disable_warnings()
    CVESCAN=CVE()
    CVESCAN.cve_scan()
    CVESCAN.AliVul_scan()
    CVESCAN.email()
