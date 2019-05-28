# 信息内容安全实验

## 需求

* 抓取http协议的webmail相关信息

## 环境

* Ubuntu18.04
* gcc
* TOM邮箱 `http://mail.tom.com`
* 依赖库: libnet libnids libpcap

## 功能

* 抓取登录者的用户名密码
* 获取发送邮件的发件人/收件人/时间/主题/内容
* 对内容urldecode
* 按'&'分行

## 运行
clone本仓库之后,编译
`gcc -o nids nids.c -lnids -lpcap -lnet`
运行
`sudo ./nids`

* 有时因网络问题需要抓取多次才能抓到包

