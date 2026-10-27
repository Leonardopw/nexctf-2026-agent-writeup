# Ambitious Mission · 笔记

## 关键点
- 目标：`http://pv5cl84fwfwuwkuz.neu-nex.fun`；首页是单文件上传表单，落盘 `/upload/<原始文件名>`。
- 后端指纹：`Server: nginx` + `X-Powered-By: PHP/8.2.33`，但 404 页是 `Apache/2.4.68 (Debian)` → nginx 反代 Apache + mod_php。
- 上传过滤（index.php 源码）：
  - 黑名单正则 `\.(php[0-9]?|phtml|pht|phar|shtml|shtm|cgi|pl|py|sh|asp|aspx|jsp)/i`；
  - 图片扩展名（jpg/jpeg/png/gif）要过 `getimagesize()`；
  - **非图片扩展名直接放行**（含 `.htaccess`、`.inc`、`.user.ini`）。
- 真洞在 `read.php`：`unserialize($_GET['data'])` + 三个类构成的 POP 链
  `Store::__destruct -> echo $item -> Wrapper::__toString -> $obj->read() -> Reader::__call -> file_get_contents($file)`，`Reader::$file` 默认 `/flag`。
- 上传链（.htaccess `AddType application/x-httpd-php .gif` + GIF 伪装 PHP）能拿到 RCE，但 `open_basedir=/var/www/html:/tmp`，直读 `/flag` 失败；RCE 只用于 dump 源码。
- 禁用函数：`system,exec,shell_exec,passthru,proc_open,popen,pcntl_exec,pcntl_fork,putenv,curl_exec,curl_multi_exec,dl`。

## 失败分支（排除理由）
- 直接传 `.php/.phtml/.php5/.phar/.pHp`：全部回「这种后缀想都别想」→ 黑名单正则在 `move_uploaded_file` 之前，排除直接 webshell。
- `.php.jpg` / `.jpg.php` / `.php.` / 大小写变形：同样被拦（正则不区分大小写、按整串 match）。
- `.user.ini` + `auto_prepend_file`：上传成功，但后端是 Apache+mod_php，不读 .user.ini，排除。
- `read.php` 换 `file/f/name/path/src/url/data...` 参数、POST 表单、Cookie 注入：一律 200 空 → 初判端点失效。
  - 真实原因：首个空响应被代理缓存（响应头 `Vary: Accept-Encoding` 出现两次）。加 `Cache-Control: no-cache`、改 POST、或走 `/read.php/x` PATH_INFO 都能绕过缓存，回显正常。
- RCE 直读 `/flag` → `false`；`scandir('/')` → `false`：`open_basedir` 限制，排除「靠上传拿 flag」。
- 用 PHP `file_get_contents('http://127.0.0.1/read.php?...')` 自请求：单 worker 死锁，curl 超时 28，后续不再自请求。

## 时间线
- T0 13:40:42 收到题目，建骨架 + recon（nginx + PHP 8.2.33）。
- T1 13:41 上传点确认：`/upload/test.jpg` 可直读；.php 系后缀全拦。
- T2 13:42 `read.php` 恒空，参数盲试无果。
- T3 13:43 上传 `.htaccess`（AddType .gif→php）+ GIF 伪装 shell → RCE（shell_exec 禁用）。
- T4 13:44 dump `/var/www/html/index.php`、`read.php` 源码，看到 POP 链。
- T5 13:45 本地 include 验证链输出 HELLO；确认响应被缓存。
- T6 13:46 `read.php?data=<chain>` + no-cache → `nex{AmBL7loUs_MIS510n_6qm62mgz}`。
- T7 13:48 清理上传物（.htaccess/shell/source dumper/test.jpg），`LEFT=.,..,index.html`。

## 可复用 TTP
- 上传黑名单只列 php 系后缀时，试 `.htaccess`（无扩展名）→ `AddType application/x-httpd-php .gif` 把图片后缀变成 PHP。
- 判断后端：404 页 `Server` 与响应头不一致时，多半 nginx 反代 Apache；`.htaccess` 只有 Apache 吃。
- `getimagesize()` 校验可用 `GIF89a` 头通过；RCE 被 disable_functions 拦时，`file_get_contents`/`scandir`/`glob` 足够 dump 源码。
- PHP 对象注入最小链：`__destruct` 回显 → `__toString` → 调不存在方法触发 `__call`。
- Web 响应「稳定 200 空」先别判死：加 `Cache-Control: no-cache`、换方法、换 PATH_INFO 复测，可能是代理缓存。

## 环境踩坑
- Windows Defender 会把含 PHP 开标签的 evidence 文本判毒（Get-Content 报 contains a virus、Python 打开报 EINVAL，文件还会被静默清掉）。源码 dump 一律先 base64 再落盘：`evidence/step4_resp.txt`（含 SRC_B64 段）配合 `evidence/step4_read.php.b64` 解码。
- PowerShell 内联 here-string 写 PHP（含 include/$_GET）会被 AV 拦成 ParserError；payload 先用 write 落成文件，再用 curl -F 上传。
