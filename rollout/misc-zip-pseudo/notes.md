# 压缩包（伪加密）· 笔记（已解）

## 关键点
- 附件 293 字节，含 `flag.txt`(28B) 与 `readme.txt`(48B)；zip 的 **general purpose bit 0**（0x0001，加密位）
  在本地头和中央目录里都被置位，所以普通解压工具会提示要密码。
- 但压缩数据其实是**明文 deflate**：`flag.txt` csz=30/usz=28、`readme.txt` csz=53/usz=48，
  CRC 正常（0x44944762 / 0x783ca1b8）——伪加密只改了标志位，没有真加密。
- 修复：把 4 处 flag（2 个本地头 + 2 个中央目录）的 bit0 清掉，再正常 inflate。
- readme 原文（UTF-8）：`看起来需要密码，但真的是这样吗？`
- flag.txt：`nex{nEveR_g0nnA_g1ve_You_Up}`

## 判定
- 清标志后 `zipfile.testzip()` 通过（CRC 全部匹配），说明数据完整、确实没加密；
- 解出的 flag 命中 `nex{...}` 正则。

## 失败分支（排除理由）
- 先用常规 `Expand-Archive` / `zipfile`：报“需要密码”，但本题是伪加密，不需要爆破密码；
- 不猜密码、不跑 fcrackzip：csz/usz/CRC 都正常，说明不是真 ZipCrypto/AES 加密。

## 时间线
- 17:28:11 收附件，检查 flag_bits=0x1；
- 17:28:3x 清 4 处 bit0，解压；
- 17:28:44 读出 flag。

## 可复用 TTP
- Zip 伪加密判定：`flag_bits & 1` 置位，但 `compress_size ≈ file_size` 且 CRC 非 0、数据以 deflate 头开始
  → 直接清 bit0 再解压（本地头偏移 6、中央目录偏移 8，各 2 字节）。
- 也有变种是只改本地头或只改中央目录，要两处都扫。
- 真加密时数据是 ZipCrypto 头或 AES 的 `PK` 扩展；伪加密的数据就是普通 deflate 流。
