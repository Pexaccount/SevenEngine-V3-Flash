# SevenEngine V3 Rev

LightGBM 静态 PE 检测引擎（独立部署版）。

## 文件

```
SevenEngineV3Rev\
├─ SevenEngine.py     主引擎（自包含，阈值已内置）
└─ Model\
   └─ SevenML.onnx    模型文件（实际为 LightGBM 格式，不可改名/移位）
```

部署只需以上两个文件，放到任何目录、任何机器均可运行。

## 环境

- Python 3.13（3.10+ 均可）

```
pip install numpy lightgbm queue
```

- lightgbm 为延迟依赖：引擎启动不检查，`load_model()` 加载模型时才校验，缺失时报 `lightgbm not installed`
- 其余全部为标准库（struct / zlib / re / threading / queue / math），无其他第三方依赖
- 特征提取 1086 维，单文件约 20~80ms

## 用法

```
python SevenEngine.py <文件或目录>
```

- 路径带空格**不需要加引号**（引擎会自动拼合），加引号也可以
- 目录扫描为 10 线程，边遍历边扫

## 判定规则

- 按 **MZ 魔数**识别 PE，完全不看扩展名（改名的 PE 照样检）
- 非 PE 文件 → `Error`
- LightGBM 输出 0~100 分：
  - **Score ≥ 82 → Malware**（82 本身即恶意）
  - **Score < 82 → Clean**

阈值写死在 `SevenEngine.py` 第 35 行 `MALWARE_THRESHOLD = 82`，改分界线只动这一处。

## 输出格式

单文件：

```
Return:ML:Gen.Malware
Score:99
```

```
Return:ML:Clean
Score:32
```

非 PE：

```
Return:Error
Score:None
```

目录：

```
[Malware] 1.dll | Score:99
[Clean] 2.dll | Score:0
[Error] 3.png | Score:None
------[Return]------
Malware | 1.dll | Score:99
Malware:1 | Clean:1 |Error:1
```

## 注意

- `Model\SevenML.onnx` 必须与 `SevenEngine.py` 保持相对位置（引擎按自身所在目录找 `Model\SevenML.onnx`）
- 模型为 1086 维特征（含节区属性 / Rich Header / 导出表 / 资源 / 签名校验 / 敏感 API 词表 / 字符串计数），配套训练于 122143 样本（白 84415 / 黑 38663），检测率 88.43%，FPR 0.15%
- 扫描大目录时进度实时打印，无需额外参数
