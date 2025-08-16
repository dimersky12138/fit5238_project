# 导入所需模块
import pefile          # 用于解析 Windows PE 文件（如 exe, dll）
import os              # 操作系统接口
import array           # 高效处理数值数组
import math            # 数学函数
import pickle          # 序列化模块
import joblib          # 专门用于加载大型 sklearn 模型
import sys             # 命令行参数支持
import argparse        # 可用于解析命令行参数（虽然未使用）

# ----------------------------------------
# 计算香农熵（衡量数据的随机性，常用于检测压缩/加密数据）
def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0]*256)  # 初始化 256 个字节的出现频次数组
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)
    return entropy

# ----------------------------------------
# 提取 PE 文件的资源段信息：[熵值, 大小]
def get_resources(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(
                                    resource_lang.data.struct.OffsetToData,
                                    resource_lang.data.struct.Size
                                )
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)
                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources

# ----------------------------------------
# 提取 PE 文件的版本信息（如：ProductVersion, FileVersion等）
def get_version_info(pe):
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res

# ----------------------------------------
# 核心函数：提取一个 PE 文件的各种静态特征
def extract_infos(fpath):
    res = {}
    pe = pefile.PE(fpath)

    # 文件头信息（FILE_HEADER 和 OPTIONAL_HEADER）
    res['Machine'] = pe.FILE_HEADER.Machine
    res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics'] = pe.FILE_HEADER.Characteristics
    res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        res['BaseOfData'] = 0
    res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    # 节区信息（数量、熵、大小等）
    res['SectionsNb'] = len(pe.sections)
    entropy = list(map(lambda x: x.get_entropy(), pe.sections))
    res['SectionsMeanEntropy'] = sum(entropy)/float(len(entropy))
    res['SectionsMinEntropy'] = min(entropy)
    res['SectionsMaxEntropy'] = max(entropy)

    raw_sizes = list(map(lambda x: x.SizeOfRawData, pe.sections))
    res['SectionsMeanRawsize'] = sum(raw_sizes)/float(len(raw_sizes))
    res['SectionsMinRawsize'] = min(raw_sizes)
    res['SectionsMaxRawsize'] = max(raw_sizes)

    virtual_sizes = list(map(lambda x: x.Misc_VirtualSize, pe.sections))
    res['SectionsMeanVirtualsize'] = sum(virtual_sizes)/float(len(virtual_sizes))
    res['SectionsMinVirtualsize'] = min(virtual_sizes)
    res['SectionMaxVirtualsize'] = max(virtual_sizes)

    # 导入表信息
    try:
        res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['ImportsNb'] = len(imports)
        res['ImportsNbOrdinal'] = 0  # 忽略基于 ordinal 的导入
    except AttributeError:
        res['ImportsNbDLL'] = 0
        res['ImportsNb'] = 0
        res['ImportsNbOrdinal'] = 0

    # 导出表信息
    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        res['ExportNb'] = 0

    # 资源信息（使用之前定义的函数）
    resources = get_resources(pe)
    res['ResourcesNb'] = len(resources)
    if len(resources) > 0:
        entropy = list(map(lambda x: x[0], resources))
        sizes = list(map(lambda x: x[1], resources))
        res['ResourcesMeanEntropy'] = sum(entropy) / float(len(entropy))
        res['ResourcesMinEntropy'] = min(entropy)
        res['ResourcesMaxEntropy'] = max(entropy)
        res['ResourcesMeanSize'] = sum(sizes) / float(len(sizes))
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else:
        res.update({
            'ResourcesMeanEntropy': 0, 'ResourcesMinEntropy': 0, 'ResourcesMaxEntropy': 0,
            'ResourcesMeanSize': 0, 'ResourcesMinSize': 0, 'ResourcesMaxSize': 0
        })

    # 加载配置段大小
    try:
        res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res['LoadConfigurationSize'] = 0

    # 版本信息字段数量
    try:
        version_infos = get_version_info(pe)
        res['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0

    return res

# ----------------------------------------
# 程序主入口：执行分类流程
if __name__ == '__main__':
    # 加载已训练好的模型和特征列表
    clf = joblib.load('Classifier/classifier.pkl')
    features = pickle.loads(open(os.path.join('Classifier/features.pkl'), 'rb').read())

    # 从命令行传入的 PE 文件路径中提取特征
    data = extract_infos(sys.argv[1])

    # 只保留模型所需的特征顺序
    pe_features = list(map(lambda x: data[x], features))
    print("Features used for classification: ", pe_features)

    # 进行预测（0=malicious, 1=legitimate）
    res = clf.predict([pe_features])[0]
    print('The file %s is %s' % (os.path.basename(sys.argv[1]), ['malicious', 'legitimate'][res]))
