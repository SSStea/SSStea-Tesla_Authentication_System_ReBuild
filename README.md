# Tesla Authentication System（原生 Visual Studio 工程）

本目录不使用 CMake。Windows GUI 和 Linux NodeAgent 分别由两个原生 Visual Studio 解决方案管理，算法、协议、加密、指标和负载源码只保留一份。

## 目录

```text
src/
├─ algorithm/       TESLA 算法和认证运行时
├─ crypto/          OpenSSL 密码实现
├─ metrics/         指标与性能计数
├─ protocol/        TCP、UDP 与控制协议
├─ workload/        文本和文件负载
├─ node/            Linux NodeAgent
└─ gui/
   ├─ shared/       GUI 共用控件
   ├─ manager/
   ├─ pc_node/
   ├─ uav_monitor/
   └─ attack_test/

projects/
├─ TeslaSources.props          两个平台共用的唯一源码清单
├─ TeslaWindows.props          Windows、Qt 和 OpenSSL 公共设置
├─ TeslaQtApplication.props    四个 GUI 的公共 Qt 设置
├─ gui/TeslaGui.sln
└─ linux/TeslaLinux.sln

third_party/nlohmann/          固定版本的 JSON 单头文件
out/                           本地生成物，不提交 Git
```

每个源码模块中的 `.h` 和 `.cpp` 放在同一目录，不再使用 `common/<module>/include/tesla/<namespace>/src` 多层结构。

## Windows GUI

环境：

- Visual Studio 2022，安装“使用 C++ 的桌面开发”；
- Qt VS Tools；
- Qt 6.10.2 `msvc2022_64`；
- OpenSSL Win64。

打开：

```text
projects/gui/TeslaGui.sln
```

选择 `Release | x64`，执行“生成解决方案”。解决方案包含一个公共静态库和四个 GUI 应用：

```text
TeslaRuntime
TeslaManagerGui
TeslaPcNodeGui
TeslaUavMonitorGui
TeslaAttackTestGui
```

输出：

```text
out/windows/Release/tesla_manager_gui.exe
out/windows/Release/tesla_pc_node_gui.exe
out/windows/Release/tesla_uav_monitor_gui.exe
out/windows/Release/tesla_attack_test_gui.exe
```

Qt 和 OpenSSL 的默认位置集中在 `projects/TeslaWindows.props`：

```xml
<TeslaQtInstall>6.10.2_msvc2022_64</TeslaQtInstall>
<OpenSslRoot>C:\Program Files\OpenSSL-Win64</OpenSslRoot>
```

其他电脑只需修改这一处，不需要逐个修改五个项目。

Visual Studio 调试时由 Qt VS Tools 提供 Qt 环境。要把 EXE 复制到没有安装 Qt 的 Windows 电脑，使用对应 Qt 版本的 `windeployqt`，并同时复制 OpenSSL 的 `libcrypto-3-x64.dll`。

## Linux 远程生成

Linux 机器安装：

```bash
sudo apt update
sudo apt install build-essential gdb rsync zip libssl-dev
```

Visual Studio 安装“使用 C++ 的 Linux 和嵌入式开发”，然后：

1. 打开“工具 → 选项 → 跨平台 → 连接管理器”。
2. 添加目标 Linux 的 IP、SSH 用户、端口和认证信息。
3. 打开 `projects/linux/TeslaLinux.sln`。
4. 右击 `TeslaNodeAgent`，打开“属性 → 常规”。
5. 在“远程生成计算机”中选择对应的 IP。
6. 选择 `Release | x64`，执行“生成解决方案”。

项目使用 GCC 和 C++17，把源码复制到目标机器后进行编译。远程目录固定为：

```text
源码：~/tesla-auth/source
中间文件：~/tesla-auth/obj/Release
程序：~/tesla-auth/bin/Release/tesla_node_agent
```

目标 IP 不写入共享工程文件。Visual Studio 会把个人选择保存到不提交 Git 的 `.vcxproj.user`，因此同一套解决方案可以在不同电脑上选择不同 IP。

## 添加源码

公共模块使用通配清单。把新的 `.h/.cpp` 放进以下任一目录后，会自动进入 Windows 公共库和 Linux 应用，无需修改两套工程：

```text
src/algorithm
src/crypto
src/metrics
src/protocol
src/workload
```

GUI 普通 `.cpp` 也按各自目录自动加入。新增包含 `Q_OBJECT` 的 GUI 头文件时，应在对应 `.vcxproj` 中增加一个 `QtMoc` 项；PC 和 UAV 项目当前采用显式 `QtMoc` 清单，避免对普通头文件运行 moc。

## 当前范围

新目录只包含两套正式产品解决方案。旧仓库中的阶段性测试和历史构建产物没有复制，以免重新引入大量测试项目、构建目录和发布目录。原仓库保持不变，可继续作为迁移对照。
