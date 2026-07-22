#pragma once

#include "protocol/AuthenticationControl.h"
#include "protocol/MonitorControl.h"

#include <QHash>
#include <QList>
#include <QPair>
#include <QString>

#include <string>

namespace tesla::gui
{
inline QString strPacketAuthenticationStatusDisplay(
    protocol::PacketAuthenticationStatus statusAuthentication
)
{
    switch (statusAuthentication)
    {
    case protocol::PacketAuthenticationStatus::Generated:
        return QStringLiteral("已生成");
    case protocol::PacketAuthenticationStatus::Pending:
        return QStringLiteral("待校验");
    case protocol::PacketAuthenticationStatus::Passed:
        return QStringLiteral("通过");
    case protocol::PacketAuthenticationStatus::Failed:
        return QStringLiteral("失败");
    }

    return QStringLiteral("未知");
}

inline QString strAuthenticationFailureTypeDisplay(
    protocol::AuthenticationFailureType typeFailure
)
{
    switch (typeFailure)
    {
    case protocol::AuthenticationFailureType::MacFailed:
        return QStringLiteral("MAC校验失败");
    case protocol::AuthenticationFailureType::MessageConflict:
        return QStringLiteral("篡改");
    case protocol::AuthenticationFailureType::FastGroupFailed:
        return QStringLiteral("快速组校验失败");
    case protocol::AuthenticationFailureType::GroupTauFailed:
        return QStringLiteral("分组标签校验失败");
    case protocol::AuthenticationFailureType::DetectionThresholdExceeded:
        return QStringLiteral("超过检测阈值");
    case protocol::AuthenticationFailureType::DuplicateDatagram:
        return QStringLiteral("重放报文");
    case protocol::AuthenticationFailureType::ArrivalWindowExpired:
        return QStringLiteral("超过到达时间窗口");
    case protocol::AuthenticationFailureType::ExpiredChainDatagram:
        return QStringLiteral("密钥链报文已过期");
    case protocol::AuthenticationFailureType::MissingPacket:
        return QStringLiteral("丢包");
    case protocol::AuthenticationFailureType::IncompleteGroupTags:
        return QStringLiteral("分组标签不完整");
    case protocol::AuthenticationFailureType::UnverifiableMissingBaseline:
        return QStringLiteral("缺少可校验的基准报文");
    case protocol::AuthenticationFailureType::UnknownContext:
        return QStringLiteral("认证上下文未知");
    case protocol::AuthenticationFailureType::ProtocolError:
        return QStringLiteral("协议错误");
    case protocol::AuthenticationFailureType::InvalidSchedulingOverrun:
        return QStringLiteral("调度超过运行时限");
    case protocol::AuthenticationFailureType::AbnormalRecordLimitReached:
        return QStringLiteral("异常记录数量达到上限");
    }

    return QStringLiteral("未知异常");
}

inline QString strAuthenticationErrorCodeDisplay(
    const std::string& strErrorCode
)
{
    static const QHash<QString, QString> MAP_ERROR_CODES{
        {QStringLiteral("MONITOR_CONFIG_FORBIDDEN"),
         QStringLiteral("监控端无权修改认证配置")},
        {QStringLiteral("MONITOR_CONTROL_FORBIDDEN"),
         QStringLiteral("监控端无权控制认证轮次")},
        {QStringLiteral("MONITOR_FILE_FORBIDDEN"),
         QStringLiteral("监控端无权上传认证文件")},
        {QStringLiteral("UNSUPPORTED_AUTH_CONTROL"),
         QStringLiteral("不支持的认证控制消息")},
        {QStringLiteral("INVALID_FILE_PAYLOAD"),
         QStringLiteral("文件载荷无效")},
        {QStringLiteral("INVALID_AUTH_CONFIG"),
         QStringLiteral("认证配置无效")},
        {QStringLiteral("INVALID_TEXT_PAYLOAD"),
         QStringLiteral("文本载荷无效")},
        {QStringLiteral("FAULT_PLAN_REJECTED"),
         QStringLiteral("发送侧故障计划被拒绝")},
        {QStringLiteral("ATTACK_SOURCE_MAPPING_REJECTED"),
         QStringLiteral("攻击测试来源映射被拒绝")},
        {QStringLiteral("TIME_UNSYNCHRONIZED"),
         QStringLiteral("节点时间未同步")},
        {QStringLiteral("ROUND_COMMAND_REJECTED"),
         QStringLiteral("认证轮次命令被拒绝")}
    };

    const QString strOriginal = QString::fromStdString(strErrorCode);
    const auto itrCode = MAP_ERROR_CODES.constFind(strOriginal);
    return itrCode == MAP_ERROR_CODES.constEnd()
        ? QStringLiteral("未知错误")
        : itrCode.value();
}

inline QString strAuthenticationReasonDisplay(const std::string& strReason)
{
    const QString strOriginal = QString::fromStdString(strReason);
    if (strOriginal.isEmpty())
    {
        return QStringLiteral("无");
    }

    static const QHash<QString, QString> MAP_EXACT_TRANSLATIONS{
        {QStringLiteral("Disclosed key accepted"),
         QStringLiteral("披露密钥校验通过")},
        {QStringLiteral("Disclosed key rejected"),
         QStringLiteral("披露密钥校验失败")},
        {QStringLiteral("Disclosed key does not match the configured commitment chain"),
         QStringLiteral("披露密钥与配置的承诺密钥链不匹配")},
        {QStringLiteral("Waiting for disclosed key"),
         QStringLiteral("等待披露密钥")},
        {QStringLiteral("Native packet MAC passed"),
         QStringLiteral("TESLA报文MAC校验通过")},
        {QStringLiteral("Native packet MAC failed"),
         QStringLiteral("TESLA报文MAC校验失败")},
        {QStringLiteral("Message recalculated MAC differs from the received MAC"),
         QStringLiteral("根据Message重新计算的MAC与接收MAC不一致")},
        {QStringLiteral("Conflicting candidate MAC passed"),
         QStringLiteral("篡改副本的MAC校验通过")},
        {QStringLiteral("Conflicting candidate MAC failed"),
         QStringLiteral("篡改副本的MAC校验失败")},
        {QStringLiteral("Improved group authentication passed"),
         QStringLiteral("S-TESLA分组校验通过")},
        {QStringLiteral("Improved group authentication rejected this packet"),
         QStringLiteral("S-TESLA分组校验拒绝该报文")},
        {QStringLiteral("FastGroupTag failed and KS+RS fallback was executed"),
         QStringLiteral("快速组标签校验失败，已执行KS+RS校验")},
        {QStringLiteral("Improved group did not contain a complete tau/FastGroupTag set"),
         QStringLiteral("S-TESLA分组未包含完整的τ/快速组标签集合")},
        {QStringLiteral("Located bad-packet candidates exceed the configured threshold"),
         QStringLiteral("定位到的异常报文候选数量超过配置阈值")},
        {QStringLiteral("Expected packet slot was not received"),
         QStringLiteral("未收到预期报文")},
        {QStringLiteral("Identical datagram received again"),
         QStringLiteral("再次收到完全相同的报文")},
        {QStringLiteral("Identical candidate datagram was received repeatedly"),
         QStringLiteral("重复收到完全相同的候选报文")},
        {QStringLiteral("Conflicting candidate duplicate received"),
         QStringLiteral("收到重复的篡改副本")},
        {QStringLiteral("Identical conflicting candidate was received repeatedly"),
         QStringLiteral("重复收到完全相同的篡改副本")},
        {QStringLiteral("Per-packet candidate version limit reached"),
         QStringLiteral("单个报文的候选版本数量达到上限")},
        {QStringLiteral("Conflicting candidate retained without replacing the baseline"),
         QStringLiteral("保留篡改副本且不替换正常报文基准")},
        {QStringLiteral("Same sender, chain and packet index carried a different datagram"),
         QStringLiteral("相同Sender、密钥链和报文编号携带了不同报文")},
        {QStringLiteral("Repeated attack candidate retained"),
         QStringLiteral("已保留重复的攻击候选报文")},
        {QStringLiteral("Attack candidate version limit reached"),
         QStringLiteral("攻击候选报文版本数量达到上限")},
        {QStringLiteral("Packet arrived after its assigned authentication window"),
         QStringLiteral("报文在所属认证时间窗口结束后到达")},
        {QStringLiteral("Attack datagram arrived outside every data interval"),
         QStringLiteral("攻击测试报文未在任何数据间隔内到达")},
        {QStringLiteral("ArrivalWindowExpired: no active data interval"),
         QStringLiteral("超过到达时间窗口：当前没有活动的数据间隔")},
        {QStringLiteral("ArrivalWindowExpired: assigned interval safety deadline passed"),
         QStringLiteral("超过到达时间窗口：所属间隔的安全截止时间已过")},
        {QStringLiteral("UDP authentication payload failed context-aware decoding"),
         QStringLiteral("UDP认证载荷无法根据当前上下文完成解析")},
        {QStringLiteral("UDP source and chain ID do not match an active trusted context"),
         QStringLiteral("UDP来源与密钥链编号不匹配任何活动认证上下文")},
        {QStringLiteral("Receiver authenticated the complete text round"),
         QStringLiteral("Receiver已完成整轮文本认证")},
        {QStringLiteral("Receiver authenticated and recovered the complete file"),
         QStringLiteral("Receiver已完成整轮认证并恢复完整文件")},
        {QStringLiteral("Receiver detected incomplete or inconsistent protocol data"),
         QStringLiteral("Receiver检测到协议数据不完整或不一致")},
        {QStringLiteral("Receiver did not authenticate every expected text packet"),
         QStringLiteral("Receiver未能认证全部预期文本报文")},
        {QStringLiteral("Receiver did not authenticate every expected file packet"),
         QStringLiteral("Receiver未能认证全部预期文件报文")},
        {QStringLiteral("Receiver timed out waiting for the final disclosed key"),
         QStringLiteral("Receiver等待最终披露密钥超时")},
        {QStringLiteral("Receiver round stopped"),
         QStringLiteral("Receiver轮次已停止")},
        {QStringLiteral("Sender completed all data and disclosure intervals"),
         QStringLiteral("Sender已完成全部数据间隔和密钥披露间隔")},
        {QStringLiteral("Authentication interval exceeded its runtime deadline"),
         QStringLiteral("认证间隔超过运行截止时间")},
        {QStringLiteral("Authentication interval exceeded its runtime deadline; remaining datagrams were not sent"),
         QStringLiteral("认证间隔超过运行截止时间，剩余报文未发送")},
        {QStringLiteral("Round stopped"),
         QStringLiteral("轮次已停止")},
        {QStringLiteral("Qt multicast send queue reported a socket failure"),
         QStringLiteral("Qt组播发送队列报告Socket发送失败")},
        {QStringLiteral("File recovery encountered a non-authenticated slot"),
         QStringLiteral("文件恢复过程中遇到未通过认证的报文位置")},
        {QStringLiteral("Receiver authenticated the file but atomic persistence failed"),
         QStringLiteral("Receiver已认证文件，但原子化落盘失败")},
        {QStringLiteral("Node has no prepared sender or receiver context"),
         QStringLiteral("节点没有准备好的Sender或Receiver认证上下文")},
        {QStringLiteral("Sender authentication configuration is missing"),
         QStringLiteral("缺少Sender认证配置")},
        {QStringLiteral("Sender configuration cannot change during an active round"),
         QStringLiteral("活动轮次期间不能修改Sender配置")},
        {QStringLiteral("Receiver configuration cannot change during an active round"),
         QStringLiteral("活动轮次期间不能修改Receiver配置")},
        {QStringLiteral("Configured key-chain length does not match packet schedule"),
         QStringLiteral("配置的密钥链长度与报文计划不匹配")},
        {QStringLiteral("File payload chain ID does not match the sender context"),
         QStringLiteral("文件载荷的密钥链编号与Sender上下文不匹配")},
        {QStringLiteral("Text payload chain ID does not match the sender context"),
         QStringLiteral("文本载荷的密钥链编号与Sender上下文不匹配")},
        {QStringLiteral("File payload size does not match the sender configuration"),
         QStringLiteral("文件载荷大小与Sender配置不匹配")},
        {QStringLiteral("Authentication schedule cannot fit measured generation, send budget and safety margin"),
         QStringLiteral("认证计划无法容纳实测生成耗时、发送预算和安全余量")},
        {QStringLiteral("Attack source mapping target does not match a receiver context"),
         QStringLiteral("攻击测试来源映射目标与Receiver上下文不匹配")},
        {QStringLiteral("Attack source mapping must be installed before start with a future expiry"),
         QStringLiteral("攻击测试来源映射必须在轮次开始前安装且有效期应晚于当前时间")},
        {QStringLiteral("Only one attack source mapping may target a sender round"),
         QStringLiteral("同一Sender轮次只允许一个攻击测试来源映射")},
        {QStringLiteral("Sender authentication configuration targets another node"),
         QStringLiteral("Sender认证配置指向了其他节点")},
        {QStringLiteral("Sender runtime is not fully configured"),
         QStringLiteral("Sender运行时尚未完成配置")},
        {QStringLiteral("Receiver runtime is not configured"),
         QStringLiteral("Receiver运行时尚未配置")},
        {QStringLiteral("Receiver runtime requires at least one context"),
         QStringLiteral("Receiver运行时至少需要一个认证上下文")},
        {QStringLiteral("Sender round start timestamp must leave preparation time"),
         QStringLiteral("Sender轮次开始时间必须预留准备时间")},
        {QStringLiteral("Receiver start schedule is invalid"),
         QStringLiteral("Receiver启动计划无效")},
        {QStringLiteral("Sender round ID must not be empty"),
         QStringLiteral("Sender轮次编号不能为空")},
        {QStringLiteral("Authentication runtime received an unsupported control message"),
         QStringLiteral("认证运行时收到了不支持的控制消息")},
        {QStringLiteral("Monitor clients cannot change sender authentication state"),
         QStringLiteral("监控端不能修改Sender认证状态")},
        {QStringLiteral("Monitor clients cannot change receiver authentication state"),
         QStringLiteral("监控端不能修改Receiver认证状态")},
        {QStringLiteral("Monitor clients cannot change the authentication payload"),
         QStringLiteral("监控端不能修改认证载荷")},
        {QStringLiteral("Monitor clients cannot control authentication rounds"),
         QStringLiteral("监控端不能控制认证轮次")},
        {QStringLiteral("Monitor clients cannot upload authentication files"),
         QStringLiteral("监控端不能上传认证文件")}
    };

    const auto itrExact = MAP_EXACT_TRANSLATIONS.constFind(strOriginal);
    if (itrExact != MAP_EXACT_TRANSLATIONS.constEnd())
    {
        return itrExact.value();
    }

    QString strDisplay = strOriginal;
    static const QList<QPair<QString, QString>> LIST_REPLACEMENTS{
        {QStringLiteral("Attack candidate retained without occupying the baseline; "),
         QStringLiteral("保留攻击候选报文且不占用正常报文基准；")},
        {QStringLiteral("TAMPERED_VARIANT: baseline passed and conflicting MAC failed"),
         QStringLiteral("篡改副本：正常报文基准校验通过，但冲突副本MAC校验失败")},
        {QStringLiteral("TAMPERED_VARIANT: attack group failed FastGroupTag and entered KS+RS"),
         QStringLiteral("篡改副本：候选分组快速组标签校验失败，已进入KS+RS校验")},
        {QStringLiteral("ATTACK_DETECTED: legal baseline passed and attack candidate failed"),
         QStringLiteral("检测到攻击异常：正常报文基准校验通过，候选报文校验失败")},
        {QStringLiteral("ATTACK_DETECTED; DETECTION_THRESHOLD_EXCEEDED"),
         QStringLiteral("检测到攻击异常；超过检测阈值")},
        {QStringLiteral("ATTACK_DETECTED; attack candidate located by KS+RS fallback"),
         QStringLiteral("检测到攻击异常；KS+RS校验已定位候选异常报文")},
        {QStringLiteral("Conflicting candidate failed native MAC verification"),
         QStringLiteral("篡改副本未通过TESLA MAC校验")},
        {QStringLiteral("DuplicateDatagram: cryptographic check passed but "),
         QStringLiteral("重放报文的密码学校验通过，但重复规则拒绝该报文；")},
        {QStringLiteral("MacFailed: current interval key rejected the attack candidate; "),
         QStringLiteral("MAC校验失败：当前间隔密钥未通过攻击候选报文校验；")},
        {QStringLiteral("DuplicateDatagram: group check passed but duplicate rule rejected it; "),
         QStringLiteral("重放报文的分组校验通过，但重复规则拒绝该报文；")},
        {QStringLiteral("GroupVerificationFailed: arrival-interval keys rejected the attack candidate; "),
         QStringLiteral("分组校验失败：到达间隔密钥未通过攻击候选报文校验；")},
        {QStringLiteral("DuplicateDatagram; "),
         QStringLiteral("重放报文；")},
        {QStringLiteral("MacFailed; "),
         QStringLiteral("MAC校验失败；")},
        {QStringLiteral("originalInterval="),
         QStringLiteral("原始间隔=")},
        {QStringLiteral("arrivalInterval="),
         QStringLiteral("到达间隔=")},
        {QStringLiteral("verificationKeyInterval="),
         QStringLiteral("验证密钥间隔=")}
    };

    for (const auto& prReplacement : LIST_REPLACEMENTS)
    {
        strDisplay.replace(prReplacement.first, prReplacement.second);
    }

    if (strDisplay != strOriginal)
    {
        return strDisplay;
    }

    return QStringLiteral("未识别原因，详细内容已保留在后台导出记录中");
}
}
