# ezrce · 笔记

## 关键点
- /rce.php 用 highlight_file 回显源码，直接读出 WAF 规则：preg_match("/flag| /")
- 过滤是大小写敏感的 `flag` 与空格；用 ${IFS} 替空格，用 fla* 通配替 flag
- id 确认 www-data；ls / 看到 /flag；cat /fla* 拿 flag

## 失败分支
- `cat</fla*` 无回显（未走通，改用 ${IFS}）
- 直接 `cat /flag` 被 WAF 拦（返回 WAF!）

## 时间线
- T0 13:14 首条消息
- T1 13:15 发现 /rce.php 源码
- T2 13:15 cmd=id 执行成功
- T3 13:16 ${IFS} + 通配符绕过
- T4 13:16 拿到 flag

## 可复用 TTP
- 源码泄露页（highlight_file）先读规则再构造 payload
- 空格三板斧：${IFS} / $IFS / %09；关键字：通配符、大小写、变量拼接
