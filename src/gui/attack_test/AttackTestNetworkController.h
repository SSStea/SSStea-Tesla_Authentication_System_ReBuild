#pragma once

#include "protocol/NodeDiscoveryMessage.h"

#include <QByteArray>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QObject>
#include <QSet>
#include <QString>
#include <QVector>

#include <cstdint>

class QTimer;
class QUdpSocket;

class AttackDatagramRecord final
{
public:
    AttackDatagramRecord(
        std::uint64_t u64RecordId,
        std::uint64_t u64CaptureTimestampMilliseconds,
        QString strSenderAddress,
        std::uint64_t u64ChainId,
        std::uint32_t u32OriginalIntervalIndex,
        std::uint32_t u32OriginalPacketIndex,
        QByteArray arrDatagram
    );

    std::uint64_t u64RecordId() const noexcept;
    std::uint64_t u64CaptureTimestampMilliseconds() const noexcept;
    const QString& strSenderAddress() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    std::uint32_t u32OriginalIntervalIndex() const noexcept;
    std::uint32_t u32OriginalPacketIndex() const noexcept;
    const QByteArray& arrDatagram() const noexcept;
    QString strMessageHex() const;

private:
    std::uint64_t m_u64RecordId;
    std::uint64_t m_u64CaptureTimestampMilliseconds;
    QString       m_strSenderAddress;
    std::uint64_t m_u64ChainId;
    std::uint32_t m_u32OriginalIntervalIndex;
    std::uint32_t m_u32OriginalPacketIndex;
    QByteArray    m_arrDatagram;
};

/** @brief 独立完成组播监听、报文副本广播和后台节点发现。 */
class AttackTestNetworkController final : public QObject
{
    Q_OBJECT

public:
    explicit AttackTestNetworkController(
        std::uint16_t u16DiscoveryPort = 37020,
        QString strMulticastAddress = QStringLiteral("239.10.10.10"),
        std::uint16_t u16MulticastPort = 39020,
        QObject* pParent = nullptr
    );
    ~AttackTestNetworkController() override;

    AttackTestNetworkController(
        const AttackTestNetworkController&
    ) = delete;
    AttackTestNetworkController& operator=(
        const AttackTestNetworkController&
    ) = delete;

    bool bStart();
    void stop() noexcept;
    bool bIsRunning() const noexcept;
    bool bMulticastListening() const noexcept;
    QString strLocalIpv4Address() const;
    QVector<AttackDatagramRecord> vecRecordSnapshot() const;

    bool bBroadcastMessageConflict(
        std::uint64_t u64RecordId,
        const QString& strMessageHex,
        QString& strError
    );
    bool bBroadcastDelayedDuplicate(
        std::uint64_t u64RecordId,
        QString& strError
    );
    bool bStartHighRateTraffic(
        std::uint32_t u32PacketsPerSecond,
        std::uint32_t u32DurationMilliseconds,
        std::uint32_t u32DatagramBytes,
        QString& strError
    );
    void stopHighRateTraffic() noexcept;
    bool bHighRateTrafficRunning() const noexcept;

signals:
    void recordsChanged();
    void roundChanged();
    void stateChanged();
    void logMessage(const QString& strMessage);

private:
    void processDiscoveryDatagrams();
    void processMulticastDatagrams();
    void sendHeartbeat();
    void sendHighRateBatch();
    bool bSendPresence(
        tesla::protocol::NodeDiscoveryMessageType typeMessage,
        const QString& strRequestId,
        const QHostAddress& adrTarget,
        std::uint16_t u16TargetPort
    );
    bool bJoinMulticastGroups();
    bool bBroadcastDatagram(const QByteArray& arrDatagram, QString& strError);
    QString strPreferredIpv4Address() const;
    QString strCreateNodeName() const;
    const AttackDatagramRecord* pFindRecord(
        std::uint64_t u64RecordId
    ) const noexcept;

    std::uint16_t m_u16DiscoveryPort;
    QString       m_strMulticastAddress;
    std::uint16_t m_u16MulticastPort;
    QString       m_strLocalIpv4Address;
    QString       m_strNodeName;
    QUdpSocket*   m_pDiscoverySocket;
    QUdpSocket*   m_pPresenceSocket;
    QUdpSocket*   m_pMulticastSocket;
    QUdpSocket*   m_pBroadcastSocket;
    QTimer*       m_pHeartbeatTimer;
    QTimer*       m_pHighRateTimer;
    QVector<AttackDatagramRecord> m_vecRecords;
    QSet<qulonglong> m_setCurrentRoundChainIds;
    QString       m_strCurrentRoundId;
    std::uint64_t m_u64NextRecordId;
    std::uint64_t m_u64RoundFirstDatagramTimestampMilliseconds;
    bool          m_bRunning;
    bool          m_bMulticastListening;
    bool          m_bHighRateTrafficRunning;
    std::uint32_t m_u32HighRatePacketsPerSecond;
    std::uint32_t m_u32HighRateDurationMilliseconds;
    std::uint32_t m_u32HighRateDatagramBytes;
    std::uint64_t m_u64HighRateSentCount;
    QElapsedTimer m_tmrHighRateElapsed;
};
