### 配置文件demo
    baidu.com
    google.com
    qq.com
    alibababa.com

### 使用方法
####### 查询域名到期时间，使用5个并发
	$ ./GetExpiryDate -f demo -d -t 5
	
####### 查询SSL证书到期时间，使用5个并发
	$ ./GetExpiryDate -f demo -s -t 5
