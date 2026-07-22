#include "AttackTestNetworkController.h"

#include "protocol/UdpAuthenticationPacketCodec.h"

#include <QAbstractSocket>
#include <QCoreApplication>
#include <QDateTime>
#include <QNetworkAddressEntry>
#include <QNetworkInterface>
#include <QSet>
#include <QTimer>
#include <QUdpSocket>

#include <algorithm>
#include <variant>

namespace
{
using namespace tesla::protocol;

constexpr qsizetype MESSAGE_OFFSET = 16;
constexpr qsizetype MESSAGE_SIZE = 32;
constexpr qsizetype MAXIMUM_RECORD_COUNT = 2000;
constexpr std::uint64_t ROUND_CHAIN_GROUPING_WINDOW_MILLISECONDS = 1000;

std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
}

ByteBuffer vecBytes(const QByteArray& arrBytes)
{
    return ByteBuffer(
        reinterpret_cast<const std::uint8_t*>(arrBytes.constData()),
        reinterpret_cast<const std::uint8_t*>(arrBytes.constData())
            + arrBytes.size()
    );
}

bool bIsPrivateIpv4(const QHostAddress& adrAddress)
{
    const quint32 u32Address = adrAddress.toIPv4Address();
    const quint8 u8First = static_cast<quint8>((u32Address >> 24U) & 0xFFU);
    const quint8 u8Second = static_cast<quint8>((u32Address >> 16U) & 0xFFU);
    return u8First == 10
        || (u8First == 172 && u8Second >= 16 && u8Second <= 31)
        || (u8First == 192 && u8Second == 168);
}
}

AttackDatagramRecord::AttackDatagramRecord(
    std::uint64_t u64RecordId,
    std::uint64_t u64CaptureTimestampMilliseconds,
    QString strSenderAddress,
    std::uint64_t u64ChainId,
    std::uint32_t u32OriginalIntervalIndex,
    std::uint32_t u32OriginalPacketIndex,
    QByteArray arrDatagram
)
    : m_u64RecordId(u64RecordId),
      m_u64CaptureTimestampMilliseconds(u64CaptureTimestampMilliseconds),
      m_strSenderAddress(std::move(strSenderAddress)),
      m_u64ChainId(u64ChainId),
      m_u32OriginalIntervalIndex(u32OriginalIntervalIndex),
      m_u32OriginalPacketIndex(u32OriginalPacketIndex),
      m_arrDatagram(std::move(arrDatagram))
{
}

std::uint64_t AttackDatagramRecord::u64RecordId() const noexcept
{
    return m_u64RecordId;
}

std::uint64_t
AttackDatagramRecord::u64CaptureTimestampMilliseconds() const noexcept
{
    return m_u64CaptureTimestampMilliseconds;
}

const QString& AttackDatagramRecord::strSenderAddress() const noexcept
{
    return m_strSenderAddress;
}

std::uint64_t AttackDatagramRecord::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

std::uint32_t
AttackDatagramRecord::u32OriginalIntervalIndex() const noexcept
{
    return m_u32OriginalIntervalIndex;
}

std::uint32_t
AttackDatagramRecord::u32OriginalPacketIndex() const noexcept
{
    return m_u32OriginalPacketIndex;
}

const QByteArray& AttackDatagramRecord::arrDatagram() const noexcept
{
    return m_arrDatagram;
}

QString AttackDatagramRecord::strMessageHex() const
{
    return QString::fromLatin1(
        m_arrDatagram.mid(MESSAGE_OFFSET, MESSAGE_SIZE).toHex().toUpper()
    );
}

AttackTestNetworkController::AttackTestNetworkController(
    std::uint16_t u16DiscoveryPort,
    QString strMulticastAddress,
    std::uint16_t u16MulticastPort,
    QObject* pParent
)
    : QObject(pParent),
      m_u16DiscoveryPort(u16DiscoveryPort),
      m_strMulticastAddress(std::move(strMulticastAddress)),
      m_u16MulticastPort(u16MulticastPort),
      m_pDiscoverySocket(new QUdpSocket(this)),
      m_pPresenceSocket(new QUdpSocket(this)),
      m_pMulticastSocket(new QUdpSocket(this)),
      m_pBroadcastSocket(new QUdpSocket(this)),
      m_pHeartbeatTimer(new QTimer(this)),
      m_pHighRateTimer(new QTimer(this)),
      m_u64NextRecordId(1),
      m_u64RoundFirstDatagramTimestampMilliseconds(0),
      m_bRunning(false),
      m_bMulticastListening(false),
      m_bHighRateTrafficRunning(false),
      m_u32HighRatePacketsPerSecond(0),
      m_u32HighRateDurationMilliseconds(0),
      m_u32HighRateDatagramBytes(0),
      m_u64HighRateSentCount(0)
{
    m_pHeartbeatTimer->setInterval(1000);
    m_pHighRateTimer->setInterval(1);

    connect(
        m_pDiscoverySocket,
        &QUdpSocket::readyRead,
        this,
        &AttackTestNetworkController::processDiscoveryDatagrams
    );
    connect(
        m_pMulticastSocket,
        &QUdpSocket::readyRead,
        this,
        &AttackTestNetworkController::processMulticastDatagrams
    );
    connect(
        m_pHeartbeatTimer,
        &QTimer::timeout,
        this,
        &AttackTestNetworkController::sendHeartbeat
    );
    connect(
        m_pHighRateTimer,
        &QTimer::timeout,
        this,
        &AttackTestNetworkController::sendHighRateBatch
    );
}

AttackTestNetworkController::~AttackTestNetworkController()
{
    stop();
}

bool AttackTestNetworkController::bStart()
{
    if (m_bRunning)
    {
        return true;
    }

    m_strLocalIpv4Address = strPreferredIpv4Address();
    m_strNodeName = strCreateNodeName();
    const QHostAddress adrLocal(m_strLocalIpv4Address);
    const bool bDiscoveryBound = m_pDiscoverySocket->bind(
        QHostAddress::AnyIPv4,
        m_u16DiscoveryPort,
        QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint
    );
    const bool bPresenceBound = m_pPresenceSocket->bind(adrLocal, 0);
    const bool bBroadcastBound = m_pBroadcastSocket->bind(adrLocal, 0);
    const bool bMulticastBound = m_pMulticastSocket->bind(
        QHostAddress::AnyIPv4,
        m_u16MulticastPort,
        QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint
    );
    if (!bDiscoveryBound || !bPresenceBound || !bBroadcastBound
        || !bMulticastBound)
    {
        emit logMessage(QStringLiteral("攻击测试端网络端口绑定失败"));
        stop();
        return false;
    }

    m_pBroadcastSocket->setSocketOption(
        QAbstractSocket::MulticastTtlOption,
        1
    );
    m_pBroadcastSocket->setSocketOption(
        QAbstractSocket::MulticastLoopbackOption,
        1
    );
    m_bMulticastListening = bJoinMulticastGroups();
    if (!m_bMulticastListening)
    {
        stop();
        return false;
    }

    m_bRunning = true;
    m_pHeartbeatTimer->start();
    sendHeartbeat();
    emit logMessage(QStringLiteral("攻击测试端已监听 %1:%2，本地地址 %3")
        .arg(m_strMulticastAddress)
        .arg(m_u16MulticastPort)
        .arg(m_strLocalIpv4Address));
    emit stateChanged();
    return true;
}

void AttackTestNetworkController::stop() noexcept
{
    stopHighRateTraffic();
    m_pHeartbeatTimer->stop();
    m_pDiscoverySocket->close();
    m_pPresenceSocket->close();
    m_pMulticastSocket->close();
    m_pBroadcastSocket->close();
    m_bRunning = false;
    m_bMulticastListening = false;
}

bool AttackTestNetworkController::bIsRunning() const noexcept
{
    return m_bRunning;
}

bool AttackTestNetworkController::bMulticastListening() const noexcept
{
    return m_bMulticastListening;
}

QString AttackTestNetworkController::strLocalIpv4Address() const
{
    return m_strLocalIpv4Address;
}

QVector<AttackDatagramRecord>
AttackTestNetworkController::vecRecordSnapshot() const
{
    return m_vecRecords;
}

bool AttackTestNetworkController::bBroadcastMessageConflict(
    std::uint64_t u64RecordId,
    const QString& strMessageHex,
    QString& strError
)
{
    const AttackDatagramRecord* pRecord = pFindRecord(u64RecordId);
    const QByteArray arrMessage = QByteArray::fromHex(strMessageHex.toLatin1());
    if (pRecord == nullptr)
    {
        strError = QStringLiteral("所选报文已经不在监听缓存中");
        return false;
    }
    if (strMessageHex.size() != MESSAGE_SIZE * 2
        || arrMessage.size() != MESSAGE_SIZE)
    {
        strError = QStringLiteral("Message必须是64个十六进制字符");
        return false;
    }

    QByteArray arrDatagram = pRecord->arrDatagram();
    arrDatagram.replace(MESSAGE_OFFSET, MESSAGE_SIZE, arrMessage);
    if (!bBroadcastDatagram(arrDatagram, strError))
    {
        return false;
    }

    emit logMessage(QStringLiteral(
        "已广播篡改副本：Sender=%1，原间隔=%2，原报文编号=%3"
    ).arg(pRecord->strSenderAddress())
        .arg(pRecord->u32OriginalIntervalIndex())
        .arg(pRecord->u32OriginalPacketIndex()));
    return true;
}

bool AttackTestNetworkController::bBroadcastDelayedDuplicate(
    std::uint64_t u64RecordId,
    QString& strError
)
{
    const AttackDatagramRecord* pRecord = pFindRecord(u64RecordId);
    if (pRecord == nullptr)
    {
        strError = QStringLiteral("所选报文已经不在监听缓存中");
        return false;
    }
    if (!bBroadcastDatagram(pRecord->arrDatagram(), strError))
    {
        return false;
    }

    emit logMessage(QStringLiteral(
        "已广播重放报文：Sender=%1，原间隔=%2，原报文编号=%3"
    ).arg(pRecord->strSenderAddress())
        .arg(pRecord->u32OriginalIntervalIndex())
        .arg(pRecord->u32OriginalPacketIndex()));
    return true;
}

bool AttackTestNetworkController::bStartHighRateTraffic(
    std::uint32_t u32PacketsPerSecond,
    std::uint32_t u32DurationMilliseconds,
    std::uint32_t u32DatagramBytes,
    QString& strError
)
{
    if (!m_bRunning || !m_bMulticastListening)
    {
        strError = QStringLiteral("组播监听服务尚未启动");
        return false;
    }
    if (m_bHighRateTrafficRunning)
    {
        strError = QStringLiteral("Dos已经在运行");
        return false;
    }
    if (u32PacketsPerSecond == 0 || u32DurationMilliseconds == 0
        || u32DatagramBytes == 0 || u32DatagramBytes > 1400)
    {
        strError = QStringLiteral("Dos参数超出允许范围");
        return false;
    }

    m_u32HighRatePacketsPerSecond = u32PacketsPerSecond;
    m_u32HighRateDurationMilliseconds = u32DurationMilliseconds;
    m_u32HighRateDatagramBytes = u32DatagramBytes;
    m_u64HighRateSentCount = 0;
    m_tmrHighRateElapsed.restart();
    m_bHighRateTrafficRunning = true;
    m_pHighRateTimer->start();
    emit logMessage(QStringLiteral("Dos已开始"));
    emit stateChanged();
    return true;
}

void AttackTestNetworkController::stopHighRateTraffic() noexcept
{
    if (!m_bHighRateTrafficRunning)
    {
        return;
    }

    m_pHighRateTimer->stop();
    m_bHighRateTrafficRunning = false;
    emit logMessage(QStringLiteral("Dos已停止，共广播 %1 条")
        .arg(m_u64HighRateSentCount));
    emit stateChanged();
}

bool AttackTestNetworkController::bHighRateTrafficRunning() const noexcept
{
    return m_bHighRateTrafficRunning;
}

void AttackTestNetworkController::processDiscoveryDatagrams()
{
    while (m_pDiscoverySocket->hasPendingDatagrams())
    {
        QHostAddress adrSource;
        quint16      u16SourcePort = 0;
        QByteArray   arrDatagram;
        arrDatagram.resize(
            static_cast<qsizetype>(m_pDiscoverySocket->pendingDatagramSize())
        );
        const qint64 nReceived = m_pDiscoverySocket->readDatagram(
            arrDatagram.data(),
            arrDatagram.size(),
            &adrSource,
            &u16SourcePort
        );
        if (nReceived <= 0)
        {
            continue;
        }

        arrDatagram.resize(static_cast<qsizetype>(nReceived));
        const NodeDiscoveryDecodeResult resMessage =
            NodeDiscoveryJsonCodec::resDecode(arrDatagram.toStdString());
        if (!std::holds_alternative<NodeDiscoveryMessage>(resMessage))
        {
            continue;
        }

        const NodeDiscoveryMessage& msgMessage =
            std::get<NodeDiscoveryMessage>(resMessage);
        if (msgMessage.typeMessage()
            == NodeDiscoveryMessageType::ObservationDisplayReset)
        {
            const ObservationDisplayResetDetails& detReset =
                std::get<ObservationDisplayResetDetails>(
                    msgMessage.varDetails()
                );
            const QString strRoundId = QString::fromStdString(
                detReset.strRoundId()
            );
            if (strRoundId != m_strCurrentRoundId)
            {
                m_strCurrentRoundId = strRoundId;
                m_vecRecords.clear();
                m_setCurrentRoundChainIds.clear();
                m_u64RoundFirstDatagramTimestampMilliseconds = 0;
                emit roundChanged();
                emit recordsChanged();
            }
            continue;
        }

        if (msgMessage.typeMessage() != NodeDiscoveryMessageType::DiscoverRequest)
        {
            continue;
        }

        const DiscoveryRequestDetails& detRequest =
            std::get<DiscoveryRequestDetails>(msgMessage.varDetails());
        static_cast<void>(bSendPresence(
            NodeDiscoveryMessageType::NodeAnnouncement,
            QString::fromStdString(detRequest.strRequestId()),
            adrSource,
            u16SourcePort
        ));
    }
}

void AttackTestNetworkController::processMulticastDatagrams()
{
    bool bChanged = false;
    while (m_pMulticastSocket->hasPendingDatagrams())
    {
        QHostAddress adrSource;
        quint16      u16SourcePort = 0;
        QByteArray   arrDatagram;
        arrDatagram.resize(
            static_cast<qsizetype>(m_pMulticastSocket->pendingDatagramSize())
        );
        const qint64 nReceived = m_pMulticastSocket->readDatagram(
            arrDatagram.data(),
            arrDatagram.size(),
            &adrSource,
            &u16SourcePort
        );
        if (nReceived < MESSAGE_OFFSET + MESSAGE_SIZE)
        {
            continue;
        }
        if (adrSource.toString() == m_strLocalIpv4Address
            && u16SourcePort == m_pBroadcastSocket->localPort())
        {
            continue;
        }

        arrDatagram.resize(static_cast<qsizetype>(nReceived));
        const UdpAuthenticationPacketHeaderDecodeResult resHeader =
            UdpAuthenticationPacketCodec::resDecodeHeader(vecBytes(arrDatagram));
        if (!std::holds_alternative<UdpAuthenticationPacketHeader>(resHeader))
        {
            continue;
        }

        const UdpAuthenticationPacketHeader& hdrPacket =
            std::get<UdpAuthenticationPacketHeader>(resHeader);
        if (hdrPacket.u32PacketIndex() == 0)
        {
            continue;
        }

        const std::uint64_t u64CaptureTimestampMilliseconds =
            u64NowMilliseconds();
        const qulonglong u64ChainId = static_cast<qulonglong>(
            hdrPacket.u64ChainId()
        );
        if (!m_setCurrentRoundChainIds.contains(u64ChainId))
        {
            const bool bStartsNewRound =
                !m_setCurrentRoundChainIds.isEmpty()
                && u64CaptureTimestampMilliseconds
                    > m_u64RoundFirstDatagramTimestampMilliseconds
                        + ROUND_CHAIN_GROUPING_WINDOW_MILLISECONDS;
            if (bStartsNewRound)
            {
                m_vecRecords.clear();
                m_setCurrentRoundChainIds.clear();
                m_u64RoundFirstDatagramTimestampMilliseconds =
                    u64CaptureTimestampMilliseconds;
                emit roundChanged();
            }
            else if (m_setCurrentRoundChainIds.isEmpty())
            {
                m_u64RoundFirstDatagramTimestampMilliseconds =
                    u64CaptureTimestampMilliseconds;
            }

            m_setCurrentRoundChainIds.insert(u64ChainId);
        }

        m_vecRecords.emplaceBack(
            m_u64NextRecordId++,
            u64CaptureTimestampMilliseconds,
            adrSource.toString(),
            hdrPacket.u64ChainId(),
            hdrPacket.u32IntervalIndex(),
            hdrPacket.u32PacketIndex(),
            arrDatagram
        );
        if (m_vecRecords.size() > MAXIMUM_RECORD_COUNT)
        {
            m_vecRecords.removeFirst();
        }
        bChanged = true;
    }

    if (bChanged)
    {
        emit recordsChanged();
    }
}

void AttackTestNetworkController::sendHeartbeat()
{
    if (!m_bRunning)
    {
        return;
    }

    QSet<QHostAddress> setTargets;
    setTargets.insert(QHostAddress::Broadcast);
    const QHostAddress adrLocal(m_strLocalIpv4Address);
    for (const QNetworkInterface& infNetwork : QNetworkInterface::allInterfaces())
    {
        for (const QNetworkAddressEntry& entAddress : infNetwork.addressEntries())
        {
            if (entAddress.ip() == adrLocal && !entAddress.broadcast().isNull())
            {
                setTargets.insert(entAddress.broadcast());
            }
        }
    }

    for (const QHostAddress& adrTarget : setTargets)
    {
        static_cast<void>(bSendPresence(
            NodeDiscoveryMessageType::Heartbeat,
            QString(),
            adrTarget,
            m_u16DiscoveryPort
        ));
    }
}

void AttackTestNetworkController::sendHighRateBatch()
{
    if (!m_bHighRateTrafficRunning)
    {
        return;
    }

    const qint64 nElapsedMilliseconds = m_tmrHighRateElapsed.elapsed();
    const std::uint64_t u64TargetCount = static_cast<std::uint64_t>(
        m_u32HighRatePacketsPerSecond
    ) * static_cast<std::uint64_t>(std::min<qint64>(
        nElapsedMilliseconds,
        m_u32HighRateDurationMilliseconds
    )) / 1000U;
    const std::uint64_t u64BatchEnd = std::min<std::uint64_t>(
        u64TargetCount,
        m_u64HighRateSentCount + 512U
    );
    QString strError;
    while (m_u64HighRateSentCount < u64BatchEnd)
    {
        QByteArray arrDatagram(
            static_cast<qsizetype>(m_u32HighRateDatagramBytes),
            static_cast<char>(0xA5)
        );
        const QByteArray arrSequence = QByteArray::number(
            m_u64HighRateSentCount,
            16
        );
        const qsizetype nCopySize = std::min(
            arrDatagram.size(),
            arrSequence.size()
        );
        arrDatagram.replace(0, nCopySize, arrSequence.left(nCopySize));
        if (!bBroadcastDatagram(arrDatagram, strError))
        {
            emit logMessage(strError);
            stopHighRateTraffic();
            return;
        }
        ++m_u64HighRateSentCount;
    }

    if (nElapsedMilliseconds >= m_u32HighRateDurationMilliseconds
        && m_u64HighRateSentCount >= u64TargetCount)
    {
        stopHighRateTraffic();
    }
}

bool AttackTestNetworkController::bSendPresence(
    NodeDiscoveryMessageType typeMessage,
    const QString& strRequestId,
    const QHostAddress& adrTarget,
    std::uint16_t u16TargetPort
)
{
    const NodeDiscoveryMessage msgPresence(NodePresenceDetails(
        typeMessage,
        strRequestId.toStdString(),
        m_strNodeName.toStdString(),
        NodeRole::AttackTester,
        0,
        false,
        false,
        u64NowMilliseconds()
    ));
    const QByteArray arrDatagram = QByteArray::fromStdString(
        NodeDiscoveryJsonCodec::strEncode(msgPresence)
    );
    return m_pPresenceSocket->writeDatagram(
        arrDatagram,
        adrTarget,
        u16TargetPort
    ) == arrDatagram.size();
}

bool AttackTestNetworkController::bJoinMulticastGroups()
{
    const QHostAddress adrGroup(m_strMulticastAddress);
    const QHostAddress adrLocal(m_strLocalIpv4Address);
    if (adrGroup.protocol() != QAbstractSocket::IPv4Protocol)
    {
        return false;
    }

    for (const QNetworkInterface& infNetwork : QNetworkInterface::allInterfaces())
    {
        for (const QNetworkAddressEntry& entAddress : infNetwork.addressEntries())
        {
            if (entAddress.ip() != adrLocal)
            {
                continue;
            }

            m_pBroadcastSocket->setMulticastInterface(infNetwork);
            if (m_pMulticastSocket->joinMulticastGroup(adrGroup, infNetwork))
            {
                return true;
            }
        }
    }

    return m_pMulticastSocket->joinMulticastGroup(adrGroup);
}

bool AttackTestNetworkController::bBroadcastDatagram(
    const QByteArray& arrDatagram,
    QString& strError
)
{
    if (!m_bRunning || arrDatagram.isEmpty())
    {
        strError = QStringLiteral("攻击测试端尚未准备好");
        return false;
    }

    if (m_pBroadcastSocket->writeDatagram(
            arrDatagram,
            QHostAddress(m_strMulticastAddress),
            m_u16MulticastPort
        ) != arrDatagram.size())
    {
        strError = QStringLiteral("广播失败：")
            + m_pBroadcastSocket->errorString();
        return false;
    }

    return true;
}

QString AttackTestNetworkController::strPreferredIpv4Address() const
{
    QString strFallback = QStringLiteral("127.0.0.1");
    int nBestScore = -10000;
    for (const QNetworkInterface& infNetwork : QNetworkInterface::allInterfaces())
    {
        const QNetworkInterface::InterfaceFlags flgInterface = infNetwork.flags();
        if (!flgInterface.testFlag(QNetworkInterface::IsUp)
            || !flgInterface.testFlag(QNetworkInterface::IsRunning)
            || flgInterface.testFlag(QNetworkInterface::IsLoopBack))
        {
            continue;
        }

        for (const QNetworkAddressEntry& entAddress : infNetwork.addressEntries())
        {
            if (entAddress.ip().protocol() != QAbstractSocket::IPv4Protocol)
            {
                continue;
            }

            int nScore = bIsPrivateIpv4(entAddress.ip()) ? 100 : 0;
            if (infNetwork.type() == QNetworkInterface::Ethernet)
            {
                nScore += 50;
            }
            else if (infNetwork.type() == QNetworkInterface::Wifi)
            {
                nScore += 40;
            }

            const QString strInterfaceText = (
                infNetwork.name() + QStringLiteral(" ")
                + infNetwork.humanReadableName()
            ).toLower();
            if (strInterfaceText.contains(QStringLiteral("vmware")))
            {
                nScore += 30;
            }
            if (strInterfaceText.contains(QStringLiteral("wsl"))
                || strInterfaceText.contains(QStringLiteral("vpn"))
                || strInterfaceText.contains(QStringLiteral("tailscale")))
            {
                nScore -= 80;
            }
            if (nScore > nBestScore)
            {
                nBestScore = nScore;
                strFallback = entAddress.ip().toString();
            }
        }
    }

    return strFallback;
}

QString AttackTestNetworkController::strCreateNodeName() const
{
    const QStringList listOctets = m_strLocalIpv4Address.split('.');
    return listOctets.size() == 4
        ? QStringLiteral("ROBUSTNESS-%1-%2")
            .arg(listOctets.last())
            .arg(QCoreApplication::applicationPid())
        : QStringLiteral("ROBUSTNESS-LOCAL-%1")
            .arg(QCoreApplication::applicationPid());
}

const AttackDatagramRecord* AttackTestNetworkController::pFindRecord(
    std::uint64_t u64RecordId
) const noexcept
{
    const auto itRecord = std::find_if(
        m_vecRecords.cbegin(),
        m_vecRecords.cend(),
        [u64RecordId](const AttackDatagramRecord& recDatagram)
        {
            return recDatagram.u64RecordId() == u64RecordId;
        }
    );
    return itRecord == m_vecRecords.cend() ? nullptr : &(*itRecord);
}
