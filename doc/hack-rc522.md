## rc522 read

```text
Sector 0, Block 0 (Manufacturer data):
DE74925E662804009010150100000000
Sector 0, Block 0 (Manufacturer data): DE74925E662804009010150100000000

Sector 0, Block 0 (Manufacturer data): 0EA7F129712804009010150100000000
Sector 0, Block 0 (Manufacturer data): 0EA7F129712804009010150100000000
```

here we find the information is store on the sector 0, block 0, the different word is the first `DE74925E66` is the head five byte.

## how to change the Sector 0, Block 0 (Manufacturer data)

- MIFARE UID 卡（中国魔术卡）：这类卡可以通过特殊指令修改 UID 和 Sector 0 的内容，常用于克隆 M1 S50 卡的数据。
- CUID 卡：这是一种优化的 UID 卡，使用常规密码验证方法来修改 Block 0 的内容，而不是通过后门指令。
- FUID 卡：这种卡在写入一次 Block 0 后会变成标准的 M1 卡，具有过防火墙的能力。
- UFUID 卡：在锁卡前与 UID 卡类似，但锁卡后会变成 M1 卡，可以通过软件解锁
