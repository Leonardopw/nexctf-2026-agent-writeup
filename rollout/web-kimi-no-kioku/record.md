# キミの記憶 · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | キミの記憶 |
| 类型 | Web / SSTI（无回显，错误布尔盲注） |
| 入口 | http://54jsekbkx1fmpdlr.neu-nex.fun |
| 耗时 | 0 日 0 时 3 分 8 秒（约；19:42:32 收题 → 19:45:40 出 flag） |
| LLM | deepseek-flash |
| flag | `nex{C0loR_Y0uR_N19Ht_knvmh44e}` |

## 2.2 目标与授权
- 授权范围：题目给定目标，未触达非靶标地址
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
nginx + Jinja2 模板渲染；单入口 GET /?name=，响应只区分『Hello/渲染不一样/渲染错误/黑名单』四态；黑名单含 self、cycler、joiner、namespace、lipsum、session

## 2.4 攻击面
?name= 直接进 Jinja2 模板渲染（无回显）；模板沙箱开放 ''__class__.__mro__[1].__subclasses__()，可触达 os._wrap_close.__init__.__globals__（environ / popen / system）

## 2.5 漏洞判定
- 类型：Web / SSTI（无回显，错误布尔盲注）
- 位置：GET /?name=<payload>；oracle 载体 {{1/0 if COND else 1}}；gadget ''.__class__.__mro__[1].__subclasses__() → _wrap_close → __init__.__globals__
- 证据：evidence/step1_solve.txt（exp.py 完整输出：逐位外带 + 整串相等复核 True）、evidence/step2_oracle.txt（四态与 oracle 校验）、evidence/home.html
- 误报排除：两条独立证据：①逐位二分外带得到 nex{C0loR_Y0uR_N19Ht_knvmh44e}；②用模板条件 G['environ']['FLAG'] == 'nex{C0loR_Y0uR_N19Ht_knvmh44e}' 触发除零返回『渲染出错了』（True），且长度==30 同时为真

## 2.6 利用链
```
GET / 确认 ?name= 模板注入 → {{7*7}} 被『渲染不一样』挡住（无回显）→ {{1/0 if 1==1 else 1}} 验证错误布尔 oracle → config/全局变量无 flag → ''__class__.__mro__[1].__subclasses__() 定位 _wrap_close → __init__.__globals__['environ'] 发现 FLAG（长 30）→ 字符比较二分逐位外带 → 整串相等复核
```

## 2.7 影响
服务端模板注入 + 沙箱逃逸：可读进程环境变量、执行系统命令；本例直接读到环境变量 FLAG

## 2.8 修复建议
不要用 render_template_string 渲染用户输入；必须渲染时用严格 sandbox（Jinja2 SandboxedEnvironment）并最小化 globals；移除 __subclasses__ 可达的 os 模块链；flag 不要放进程环境变量

## 2.9 复盘
关键是意识到『渲染出错了』可以当布尔信道；另外该沙箱的 ord 被改写，字符比较二分才稳定。
