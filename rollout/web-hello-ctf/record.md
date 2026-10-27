# Hello CTF · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | Hello CTF |
| 类型 | Web / 签到（HTML 注释泄露参数 + hex/base64 编码链） |
| 入口 | http://6o2bbxsiyusi7iel.neu-nex.fun/ |
| 耗时 | 0 日 0 时 1 分 30 秒 |
| LLM | deepseek-flash |
| flag | `nex{KFC_Crazy_Thursday_Vivo_50}` |

## 2.2 目标与授权
- 授权范围：题目域名，仅 80 端口；未触达非靶标地址
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
nginx；首页 200/233 字节；HTML 注释 <!-- 传参 ?helloctf=1 -->

## 2.4 攻击面
1) / 首页（注释泄露）2) /?helloctf=1（返回 hex）

## 2.5 漏洞判定
- 类型：Web / 签到（HTML 注释泄露参数 + hex/base64 编码链）
- 位置：/?helloctf=1
- 证据：evidence/step2_hex.txt 第 1 行；evidence/step1_home.html 第 12 行注释
- 误报排除：直接访问 / 不含 flag；必须带 helloctf=1 才返回 hex，两次请求结果一致

## 2.6 利用链
```
GET /                          -> 200  注释: ?helloctf=1
GET /?helloctf=1               -> 200  626d5634...3d3d（hex）
hex decode                     -> bmV4e0tG...fQ==（base64）
base64 decode                  -> nex{KFC_Crazy_Thursday_Vivo_50}
```

## 2.7 影响
无实际业务影响；签到题，仅泄露 flag

## 2.8 修复建议
移除 HTML 注释中的参数提示；flag 不要走可枚举参数返回

## 2.9 复盘
首页注释直接给入口，hex→base64 两步解码即出，全程无阻碍
