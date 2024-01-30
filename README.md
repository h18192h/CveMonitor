# CveMonitor
CveMonitor每天定时监控CVE上新及更新情况
网上已经有大量的脚本。这里我是直接引用大佬的脚本在上面造的轮子。原项目地址：[GitHub - JickLunlun/CveMonitoring: CVE漏洞监控推送脚本](https://github.com/JickLunlun/CveMonitoring)

## 增加功能

在大佬原脚本的基础上优化了下结果的输出，将以文本段落输出的形式改为了以表格的形式呈现，更加直观；

查看html文件时鼠标悬停行会高亮；

邮件发送增加了发送附件；

爬取漏洞等级；

对接百度翻译API对漏洞描述进行翻译；（后期打算对接chatgpt进行翻译，让翻译更加适合中国宝宝的体制）

新增aliyun漏洞库的爬取（CVE与非CVE）；

并将爬取到的数据保存到数据库；（会直接在项目根目录生成一个Vuln.db的sqlite文件）

后续还会增加数据库存储功能及其他各平台（seebug、CNVD、CNNVD、nessus）的漏洞爬取与去重以及微信公众号推送功能。

## 安装&&使用

下载到本地后安装所需要的依赖。

```shell
git clone https://github.com/h18192h/CveMonitor.git
cd CveMonitor
pip3 install -r requirements.txt
```

第189和190行，def BaiduTrans(cvecve)函数中配置好百度翻译appkey即可：

```python
appid = ''  #百度翻译APPid
appkey = ''    #百度翻译appkey
```

发送邮箱函数：def email()

发送邮箱需要开启SMTP服务

```python
smtp_server = 'smtp.exmail.qq.com'    #改为自己所用邮箱的服务器在邮箱设置中可以查到
user = ''    #邮箱账号
password = ''    #邮箱密码
sender = ''    #发件人，与user一致
receives = ['user1@qq.com','user2@gmail.com']    #收件人
```

脚本稍微完善了下当天有更新的历史CVE也会爬取，如果不需要的话可以将(.*)+?去掉，就爬取当天上新的CVE，不过当天上新的CVE大多都是还没有评级的：

```python
cve_re=re.compile(r"<A HREF = '(.+?)'>(.+?)</A>(.*)+?<br />")    #若只想爬今天上新的CVE去掉(.*)+?即可
```

配置好后python3 CveMonitor运行即可。

## 增加定时任务

```shell
$ crontab -e    #进入编辑界面
输入一下数据
0 9 * * * python /path/CveMonitor    #确保将/path/CveMonitor替换为脚本的绝对路径
```

## 结果图

![image-20231229160930286](https://github.com/h18192h/CveMonitor/assets/83074322/e5104432-8267-451d-a771-22acbd0f5ec6)
![image-20231229161100521](https://github.com/h18192h/CveMonitor/assets/83074322/905b2019-3305-4dc4-89c0-4af802ef4150)
![image-20231229161238818](https://github.com/h18192h/CveMonitor/assets/83074322/0dbedd7b-b4ac-4560-9a43-9134bea1ab70)
![image-20231229161306930](https://github.com/h18192h/CveMonitor/assets/83074322/5b3e3651-a995-4504-86b3-30ae0ab27cdf)
