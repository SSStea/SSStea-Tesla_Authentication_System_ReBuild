#include "AuthenticationMonitorWidget.h"

#include "protocol/AuthenticationControl.h"

#include <QAbstractTableModel>
#include <QButtonGroup>
#include <QColor>
#include <QComboBox>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QTableView>
#include <QTextEdit>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <utility>
#include <variant>

namespace tesla::gui
{
namespace
{
using namespace protocol;
using namespace metrics;

QString strHex(const ByteBuffer& vecBytes)
{
    static constexpr char HEX[] = "0123456789abcdef";
    QString strValue;
    strValue.reserve(static_cast<qsizetype>(vecBytes.size() * 2U));
    for (const std::uint8_t u8Value : vecBytes)
    {
        strValue.append(QLatin1Char(HEX[(u8Value >> 4U) & 0x0FU]));
        strValue.append(QLatin1Char(HEX[u8Value & 0x0FU]));
    }
    return strValue;
}

QString strCsv(const QString& strValue)
{
    QString strEscaped = strValue;
    strEscaped.replace(QLatin1Char('"'), QStringLiteral("\"\""));
    return QLatin1Char('"') + strEscaped + QLatin1Char('"');
}

QString strMetricMode(AuthenticationMetricMode modeAuthentication)
{
    return modeAuthentication == AuthenticationMetricMode::Native
        ? QStringLiteral("NATIVE")
        : QStringLiteral("IMPROVED");
}

QString strBlock(const BinaryBlock& arrValue)
{
    return strHex(ByteBuffer(arrValue.begin(), arrValue.end()));
}

QString strTime(std::uint64_t u64TimestampMilliseconds)
{
    return QDateTime::fromMSecsSinceEpoch(
        static_cast<qint64>(u64TimestampMilliseconds)
    ).toString(QStringLiteral("HH:mm:ss.zzz"));
}

QString strPacketStatus(PacketAuthenticationStatus statusAuthentication)
{
    switch (statusAuthentication)
    {
    case PacketAuthenticationStatus::Generated:
        return QStringLiteral("GENERATED");
    case PacketAuthenticationStatus::Pending:
        return QStringLiteral("PENDING");
    case PacketAuthenticationStatus::Passed:
        return QStringLiteral("PASS");
    case PacketAuthenticationStatus::Failed:
        return QStringLiteral("FAIL");
    }
    return QStringLiteral("UNKNOWN");
}

QString strFailureType(AuthenticationFailureType typeFailure)
{
    switch (typeFailure)
    {
    case AuthenticationFailureType::MacFailed:
        return QStringLiteral("MAC_FAILED");
    case AuthenticationFailureType::TamperedVariant:
        return QStringLiteral("TAMPERED_VARIANT");
    case AuthenticationFailureType::FastGroupFailed:
        return QStringLiteral("FAST_GROUP_FAILED");
    case AuthenticationFailureType::GroupTauFailed:
        return QStringLiteral("GROUP_TAU_FAILED");
    case AuthenticationFailureType::DetectionThresholdExceeded:
        return QStringLiteral("DETECTION_THRESHOLD_EXCEEDED");
    case AuthenticationFailureType::ReplayDuplicate:
        return QStringLiteral("REPLAY_DUPLICATE");
    case AuthenticationFailureType::ReplayLate:
        return QStringLiteral("REPLAY_LATE");
    case AuthenticationFailureType::ReplayExpiredChain:
        return QStringLiteral("REPLAY_EXPIRED_CHAIN");
    case AuthenticationFailureType::MissingPacket:
        return QStringLiteral("MISSING_PACKET");
    case AuthenticationFailureType::IncompleteGroupTags:
        return QStringLiteral("INCOMPLETE_GROUP_TAGS");
    case AuthenticationFailureType::UnverifiableMissingBaseline:
        return QStringLiteral("UNVERIFIABLE_MISSING_BASELINE");
    case AuthenticationFailureType::UnknownContext:
        return QStringLiteral("UNKNOWN_CONTEXT");
    case AuthenticationFailureType::ProtocolError:
        return QStringLiteral("PROTOCOL_ERROR");
    case AuthenticationFailureType::InvalidSchedulingOverrun:
        return QStringLiteral("INVALID_SCHEDULING_OVERRUN");
    case AuthenticationFailureType::AbnormalRecordLimitReached:
        return QStringLiteral("ABNORMAL_RECORD_LIMIT_REACHED");
    }
    return QStringLiteral("UNKNOWN");
}

QString strAlgorithm(AuthenticationCryptoAlgorithm algCrypto)
{
    switch (algCrypto)
    {
    case AuthenticationCryptoAlgorithm::Sha256:
        return QStringLiteral("SHA-256");
    case AuthenticationCryptoAlgorithm::Sm3:
        return QStringLiteral("SM3");
    case AuthenticationCryptoAlgorithm::Sha3_256:
        return QStringLiteral("SHA3-256");
    }
    return QStringLiteral("UNKNOWN");
}

QString strMode(UdpAuthenticationMode modeAuthentication)
{
    return modeAuthentication == UdpAuthenticationMode::Native
        ? QStringLiteral("TESLA")
        : QStringLiteral("S-TESLA");
}

QString strSource(PacketSourceType typeSource)
{
    switch (typeSource)
    {
    case PacketSourceType::NormalSender:
        return QStringLiteral("正常Sender");
    case PacketSourceType::AttackInjection:
        return QStringLiteral("攻击注入");
    case PacketSourceType::UnknownSource:
        return QStringLiteral("未知来源");
    }
    return QStringLiteral("未知");
}

bool bIsMissingFailure(AuthenticationFailureType typeFailure)
{
    return typeFailure == AuthenticationFailureType::MissingPacket
        || typeFailure == AuthenticationFailureType::UnverifiableMissingBaseline;
}

class PacketTableModel final : public QAbstractTableModel
{
public:
    explicit PacketTableModel(QObject* pParent = nullptr)
        : QAbstractTableModel(pParent)
    {
    }

    int rowCount(const QModelIndex& = QModelIndex()) const override
    {
        return static_cast<int>(m_vecPackets.size() + m_vecStandaloneFailures.size());
    }

    int columnCount(const QModelIndex& = QModelIndex()) const override
    {
        return 6;
    }

    QVariant headerData(
        int nSection,
        Qt::Orientation oriOrientation,
        int nRole
    ) const override
    {
        if (oriOrientation != Qt::Horizontal || nRole != Qt::DisplayRole)
        {
            return {};
        }
        static const std::array<const char*, 6> HEADERS{
            "时间", "方向", "Sender", "密钥编号", "报文长度", "结果"
        };
        return QString::fromUtf8(HEADERS.at(static_cast<std::size_t>(nSection)));
    }

    QVariant data(const QModelIndex& idxIndex, int nRole) const override
    {
        if (!idxIndex.isValid()
            || idxIndex.row() < 0
            || idxIndex.row() >= rowCount())
        {
            return {};
        }
        const PacketFailureControlDetails* pFailure = pStandaloneFailure(
            idxIndex.row()
        );
        if (pFailure != nullptr)
        {
            if (nRole == Qt::UserRole)
            {
                return QVariant::fromValue<qulonglong>(pFailure->u64EventId());
            }
            if (nRole == Qt::BackgroundRole)
            {
                return QColor(255, 226, 226);
            }
            if (nRole != Qt::DisplayRole)
            {
                return {};
            }

            switch (idxIndex.column())
            {
            case 0:
                return strTime(pFailure->u64TimestampMilliseconds());
            case 1:
                return QStringLiteral("RX");
            case 2:
                return QString::fromStdString(pFailure->strSenderId());
            case 3:
                return QStringLiteral("K%1").arg(pFailure->u32IntervalIndex());
            case 4:
                return QStringLiteral("—");
            case 5:
                return bIsMissingFailure(pFailure->typeFailure())
                    ? QStringLiteral("丢包")
                    : QStringLiteral("MAC/分组校验失败");
            default:
                return {};
            }
        }

        const PacketObservationControlDetails* pPacket = this->pPacket(
            idxIndex.row()
        );
        if (pPacket == nullptr)
        {
            return {};
        }
        const PacketObservationControlDetails& detPacket = *pPacket;
        if (nRole == Qt::UserRole)
        {
            return QVariant::fromValue<qulonglong>(detPacket.u64EventId());
        }
        if (nRole == Qt::BackgroundRole
            && (detPacket.statusAuthentication()
                    == PacketAuthenticationStatus::Failed
                || detPacket.typeSource() != PacketSourceType::NormalSender))
        {
            return QColor(255, 226, 226);
        }
        if (nRole != Qt::DisplayRole)
        {
            return {};
        }

        switch (idxIndex.column())
        {
        case 0:
            return strTime(detPacket.u64TimestampMilliseconds());
        case 1:
            return detPacket.dirDirection() == PacketObservationDirection::Tx
                ? QStringLiteral("TX") : QStringLiteral("RX");
        case 2:
            return QString::fromStdString(detPacket.strSenderId());
        case 3:
        {
            const std::uint32_t u32DisclosedKeyIndex =
                detPacket.u32IntervalIndex() > detPacket.u32DisclosureDelay()
                ? detPacket.u32IntervalIndex()
                    - detPacket.u32DisclosureDelay()
                : 0;
            if (std::holds_alternative<DisclosurePacketObservationDetails>(
                    detPacket.varPayloadDetails()
                ))
            {
                return QStringLiteral("披露K%1").arg(u32DisclosedKeyIndex);
            }
            const auto& detData = std::get<DataPacketObservationDetails>(
                detPacket.varPayloadDetails()
            );
            return detData.optDisclosedKey().has_value()
                ? QStringLiteral("K%1 / 披露K%2")
                    .arg(detPacket.u32IntervalIndex())
                    .arg(u32DisclosedKeyIndex)
                : QStringLiteral("K%1").arg(detPacket.u32IntervalIndex());
        }
        case 4:
            return QStringLiteral("%1 B").arg(static_cast<qulonglong>(
                detPacket.vecRawDatagram().size()
            ));
        case 5:
        {
            const auto itrFailures = m_mapPacketFailures.find(
                detPacket.u64EventId()
            );
            if (itrFailures != m_mapPacketFailures.end())
            {
                return std::any_of(
                    itrFailures->second.begin(),
                    itrFailures->second.end(),
                    [](AuthenticationFailureType typeFailure)
                    {
                        return bIsMissingFailure(typeFailure);
                    }
                ) ? QStringLiteral("丢包")
                  : QStringLiteral("MAC/分组校验失败");
            }
            return strPacketStatus(detPacket.statusAuthentication());
        }
        default:
            return {};
        }
    }

    void setRecords(
        std::vector<PacketObservationControlDetails> vecPackets,
        const std::vector<PacketFailureControlDetails>& vecFailures
    )
    {
        beginResetModel();
        m_vecPackets = std::move(vecPackets);
        m_vecStandaloneFailures.clear();
        m_mapPacketFailures.clear();
        for (const PacketFailureControlDetails& detFailure : vecFailures)
        {
            if (detFailure.u64PacketEventId() == 0)
            {
                m_vecStandaloneFailures.push_back(detFailure);
                continue;
            }

            m_mapPacketFailures[detFailure.u64PacketEventId()].push_back(
                detFailure.typeFailure()
            );
        }
        endResetModel();
    }

    const PacketObservationControlDetails* pPacket(int nRow) const
    {
        return nRow >= 0
            && nRow < static_cast<int>(m_vecPackets.size())
            ? &m_vecPackets.at(static_cast<std::size_t>(nRow))
            : nullptr;
    }

    const PacketFailureControlDetails* pStandaloneFailure(int nRow) const
    {
        const int nFailureRow = nRow - static_cast<int>(m_vecPackets.size());
        return nFailureRow >= 0
            && nFailureRow < static_cast<int>(m_vecStandaloneFailures.size())
            ? &m_vecStandaloneFailures.at(static_cast<std::size_t>(nFailureRow))
            : nullptr;
    }

    int nRowForEventId(std::uint64_t u64EventId) const
    {
        for (std::size_t nIndex = 0; nIndex < m_vecPackets.size(); ++nIndex)
        {
            if (m_vecPackets[nIndex].u64EventId() == u64EventId)
            {
                return static_cast<int>(nIndex);
            }
        }
        return -1;
    }

private:
    std::vector<PacketObservationControlDetails> m_vecPackets;
    std::vector<PacketFailureControlDetails>     m_vecStandaloneFailures;
    std::map<std::uint64_t, std::vector<AuthenticationFailureType>>
        m_mapPacketFailures;
};

enum class QuickFilter
{
    All,
    Abnormal,
    AuthenticationFailed,
    Missing
};

class PacketFilterProxyModel final : public QSortFilterProxyModel
{
public:
    explicit PacketFilterProxyModel(QObject* pParent = nullptr)
        : QSortFilterProxyModel(pParent)
    {
    }

    void setFailures(const std::vector<PacketFailureControlDetails>& vecFailures)
    {
        m_mapFailures.clear();
        for (const auto& detFailure : vecFailures)
        {
            if (detFailure.u64PacketEventId() != 0)
            {
                m_mapFailures[detFailure.u64PacketEventId()].push_back(
                    detFailure.typeFailure()
                );
            }
        }
        invalidateFilter();
    }

    void setQuickFilter(QuickFilter fltQuick)
    {
        m_fltQuick = fltQuick;
        invalidateFilter();
    }

    void setQuery(
        QString strSender,
        QString strPacket
    )
    {
        m_strSender = strSender.trimmed();
        m_strPacket = strPacket.trimmed();
        invalidateFilter();
    }

protected:
    bool filterAcceptsRow(int nSourceRow, const QModelIndex&) const override
    {
        const auto* pModel = static_cast<const PacketTableModel*>(sourceModel());
        if (pModel == nullptr)
        {
            return false;
        }

        const PacketFailureControlDetails* pStandaloneFailure
            = pModel->pStandaloneFailure(nSourceRow);
        if (pStandaloneFailure != nullptr)
        {
            if (!m_strSender.isEmpty()
                && QString::fromStdString(pStandaloneFailure->strSenderId())
                    != m_strSender)
            {
                return false;
            }
            if (!m_strPacket.isEmpty()
                && QString::number(pStandaloneFailure->u32PacketIndex())
                    != m_strPacket)
            {
                return false;
            }

            return m_fltQuick == QuickFilter::All
                || m_fltQuick == QuickFilter::Abnormal
                || (m_fltQuick == QuickFilter::Missing
                    && bIsMissingFailure(pStandaloneFailure->typeFailure()))
                || (m_fltQuick == QuickFilter::AuthenticationFailed
                    && !bIsMissingFailure(pStandaloneFailure->typeFailure()));
        }

        const PacketObservationControlDetails* pPacket = pModel->pPacket(
            nSourceRow
        );
        if (pPacket == nullptr)
        {
            return false;
        }

        if (!m_strSender.isEmpty()
            && QString::fromStdString(pPacket->strSenderId()) != m_strSender)
        {
            return false;
        }
        if (!m_strPacket.isEmpty()
            && QString::number(pPacket->u32PacketIndex()) != m_strPacket)
        {
            return false;
        }

        if (m_fltQuick == QuickFilter::All)
        {
            return true;
        }
        const auto itFailures = m_mapFailures.find(pPacket->u64EventId());
        if (itFailures == m_mapFailures.end())
        {
            return false;
        }
        if (m_fltQuick == QuickFilter::Abnormal)
        {
            return true;
        }
        return std::any_of(
            itFailures->second.begin(),
            itFailures->second.end(),
            [this](AuthenticationFailureType typeFailure)
            {
                return m_fltQuick == QuickFilter::Missing
                    ? bIsMissingFailure(typeFailure)
                    : !bIsMissingFailure(typeFailure);
            }
        );
    }

private:
    std::map<std::uint64_t, std::vector<AuthenticationFailureType>> m_mapFailures;
    QuickFilter m_fltQuick{QuickFilter::All};
    QString m_strSender;
    QString m_strPacket;
};

QString strPacketDetails(const PacketObservationControlDetails& detPacket)
{
    const std::uint32_t u32DisclosedKeyIndex =
        detPacket.u32IntervalIndex() > detPacket.u32DisclosureDelay()
        ? detPacket.u32IntervalIndex() - detPacket.u32DisclosureDelay()
        : 0;
    QStringList lstLines{
        QStringLiteral("Event ID: %1").arg(detPacket.u64EventId()),
        QStringLiteral("时间: %1").arg(strTime(detPacket.u64TimestampMilliseconds())),
        QStringLiteral("逻辑Sender ID: %1").arg(QString::fromStdString(detPacket.strSenderId())),
        QStringLiteral("Sender IP: %1").arg(QString::fromStdString(detPacket.strSenderIp())),
        QStringLiteral("实际UDP源IP: %1").arg(QString::fromStdString(detPacket.strActualSourceIp())),
        QStringLiteral("对端: %1").arg(QString::fromStdString(detPacket.strPeer())),
        QStringLiteral("来源类型: %1").arg(strSource(detPacket.typeSource())),
        QStringLiteral("Chain ID: %1").arg(detPacket.u64ChainId()),
        QStringLiteral("间隔编号: %1").arg(detPacket.u32IntervalIndex()),
        QStringLiteral("全局报文编号: %1").arg(detPacket.u32PacketIndex()),
        QStringLiteral("每间隔发包数: %1").arg(detPacket.u32PacketsPerInterval()),
        QStringLiteral("披露延迟: %1").arg(detPacket.u32DisclosureDelay()),
        QStringLiteral("认证模式: %1").arg(strMode(detPacket.modeAuthentication())),
        QStringLiteral("密码算法: %1").arg(strAlgorithm(detPacket.algCryptoAlgorithm())),
        QStringLiteral("状态: %1").arg(strPacketStatus(detPacket.statusAuthentication())),
        QStringLiteral("候选Hash: %1").arg(QString::fromStdString(detPacket.strCandidateHash())),
        QStringLiteral("重复次数: %1").arg(detPacket.u32DuplicateCount()),
        QStringLiteral("原因: %1").arg(QString::fromStdString(detPacket.strReason()))
    };

    if (const auto* pDisclosure = std::get_if<DisclosurePacketObservationDetails>(
            &detPacket.varPayloadDetails()
        ))
    {
        lstLines << QStringLiteral("类型: DISCLOSE")
                 << QStringLiteral("披露密钥编号: K%1").arg(
                        u32DisclosedKeyIndex
                    )
                 << QStringLiteral("披露Key: %1").arg(
                        strBlock(pDisclosure->arrDisclosedKey())
                    );
    }
    else
    {
        const auto& detData = std::get<DataPacketObservationDetails>(
            detPacket.varPayloadDetails()
        );
        lstLines << QStringLiteral("类型: DATA")
                 << QStringLiteral("数据密钥编号: K%1").arg(
                        detPacket.u32IntervalIndex()
                    )
                 << QStringLiteral("Message: %1").arg(
                        strBlock(detData.arrMessage())
                    );
        if (detData.optDisclosedKey().has_value())
        {
            lstLines << QStringLiteral("披露密钥编号: K%1").arg(
                u32DisclosedKeyIndex
            );
            lstLines << QStringLiteral("携带披露Key: %1").arg(
                strBlock(detData.optDisclosedKey().value())
            );
        }
        if (const auto* pNative = std::get_if<NativePacketObservationDetails>(
                &detData.varModeDetails()
            ))
        {
            lstLines << QStringLiteral("MAC: %1").arg(
                strBlock(pNative->arrPacketMac())
            );
        }
        else
        {
            const auto& detImproved = std::get<ImprovedPacketObservationDetails>(
                detData.varModeDetails()
            );
            for (std::size_t nIndex = 0;
                 nIndex < detImproved.vecSamdTau().size();
                 ++nIndex)
            {
                lstLines << QStringLiteral("τ[%1]: %2")
                    .arg(nIndex)
                    .arg(strBlock(detImproved.vecSamdTau()[nIndex]));
            }
            lstLines << QStringLiteral("FastGroupTag: %1").arg(
                detImproved.optFastGroupTag().has_value()
                    ? strBlock(detImproved.optFastGroupTag().value())
                    : QStringLiteral("本报文不携带")
            );
        }
    }
    lstLines << QStringLiteral("原始UDP字节(%1B): %2")
        .arg(static_cast<qulonglong>(detPacket.vecRawDatagram().size()))
        .arg(strHex(detPacket.vecRawDatagram()));
    return lstLines.join(QLatin1Char('\n'));
}

QString strFailureDetails(const PacketFailureControlDetails& detFailure)
{
    QStringList lstLines{
        QStringLiteral("异常类型: %1").arg(strFailureType(detFailure.typeFailure())),
        QStringLiteral("Sender: %1").arg(QString::fromStdString(detFailure.strSenderId())),
        QStringLiteral("Chain ID: %1").arg(detFailure.u64ChainId()),
        QStringLiteral("预期报文编号: %1").arg(detFailure.u32PacketIndex()),
        QStringLiteral("预期间隔编号: %1").arg(detFailure.u32IntervalIndex()),
        QStringLiteral("实际源IP: %1").arg(
            detFailure.strActualSourceIp().empty()
                ? QStringLiteral("—")
                : QString::fromStdString(detFailure.strActualSourceIp())
        ),
        QStringLiteral("失败原因: %1").arg(QString::fromStdString(detFailure.strReason()))
    };
    if (detFailure.u64PacketEventId() == 0)
    {
        lstLines << QStringLiteral("未收到报文；不存在Message、认证字段或原始UDP数据。");
    }
    if (!detFailure.vecLocatedPacketIndexes().empty())
    {
        QStringList lstIndexes;
        for (const auto u32Index : detFailure.vecLocatedPacketIndexes())
        {
            lstIndexes << QString::number(u32Index);
        }
        lstLines << QStringLiteral("定位出的坏包编号: %1").arg(
            lstIndexes.join(QStringLiteral(", "))
        );
    }
    return lstLines.join(QLatin1Char('\n'));
}
}

class AuthenticationMonitorWidget::Impl final
{
public:
    explicit Impl(AuthenticationMonitorWidget* pOwner)
        : m_pOwner(pOwner),
          m_pPacketModel(new PacketTableModel(pOwner)),
          m_pProxyModel(new PacketFilterProxyModel(pOwner)),
          m_pPacketTable(new QTableView(pOwner)),
          m_pDetailEdit(new QTextEdit(pOwner)),
          m_pSenderEdit(new QLineEdit(pOwner)),
          m_pPacketEdit(new QLineEdit(pOwner)),
          m_pAbnormalTypeCombo(new QComboBox(pOwner)),
          m_pDosLabel(new QLabel(pOwner))
    {
        m_pProxyModel->setSourceModel(m_pPacketModel);
        m_pProxyModel->setDynamicSortFilter(true);
        m_pPacketTable->setModel(m_pProxyModel);
        m_pDetailEdit->setReadOnly(true);
        m_pDetailEdit->setLineWrapMode(QTextEdit::NoWrap);
        m_pAbnormalTypeCombo->addItems({
            QStringLiteral("全部异常"),
            QStringLiteral("MAC/分组校验失败"),
            QStringLiteral("丢包")
        });
        m_pAbnormalTypeCombo->setEnabled(false);
        createPages();
        connectActions();
    }

    void setSnapshots(
        std::vector<PacketObservationControlDetails> vecPackets,
        std::vector<PacketFailureControlDetails> vecFailures,
        std::vector<DosSummaryControlDetails> vecDosSummaries
    )
    {
        m_vecPackets = vecPackets;
        m_vecFailures = vecFailures;
        m_vecDosSummaries = vecDosSummaries;
        m_pPacketModel->setRecords(std::move(vecPackets), vecFailures);
        m_pProxyModel->setFailures(vecFailures);
        refreshQuickButtonCounts();

        if (vecDosSummaries.empty())
        {
            m_pDosLabel->setText(QStringLiteral("DoS汇总：暂无"));
        }
        else
        {
            const auto& detSummary = vecDosSummaries.back();
            m_pDosLabel->setText(QStringLiteral(
                "最近%1毫秒：无效报文=%2，限速丢弃=%3，合法报文=%4，队列溢出=%5"
            )
                .arg(detSummary.u32WindowMilliseconds())
                .arg(detSummary.u64InvalidPacketCount())
                .arg(detSummary.u64RateLimitedDropCount())
                .arg(detSummary.u64LegitimatePacketCount())
                .arg(detSummary.u64ReceiveQueueOverflowCount()));
        }
    }

    void setMetricSnapshots(
        std::vector<AuthenticationMetricRecord> vecMetrics
    )
    {
        m_vecRoundArchives.clear();
        for (AuthenticationMetricRecord& varMetric : vecMetrics)
        {
            if (auto* pArchive = std::get_if<
                    AuthenticationRoundArchiveSummary
                >(&varMetric))
            {
                m_vecRoundArchives.push_back(std::move(*pArchive));
            }
        }
    }

private:
    void exportRoundArchives(bool bJson)
    {
        if (m_vecRoundArchives.empty())
        {
            QMessageBox::information(
                m_pOwner,
                QStringLiteral("导出逐轮记录"),
                QStringLiteral("当前没有已经结束的逐轮归档记录。")
            );
            return;
        }

        const QString strSuffix = bJson
            ? QStringLiteral("json")
            : QStringLiteral("csv");
        const QString strPath = QFileDialog::getSaveFileName(
            m_pOwner,
            QStringLiteral("导出本节点逐轮记录"),
            QStringLiteral("tesla-round-records-%1.%2")
                .arg(
                    QDateTime::currentDateTime().toString(
                        QStringLiteral("yyyyMMdd-HHmmss")
                    ),
                    strSuffix
                ),
            bJson ? QStringLiteral("JSON (*.json)") : QStringLiteral("CSV (*.csv)")
        );
        if (strPath.isEmpty())
        {
            return;
        }

        static const QString strCsvHeader = QStringLiteral(
            "experimentId,runId,timestamp,gitCommit,nodeId,senderId,chainId,role,"
            "authMode,cryptoAlgorithm,payloadHash,packetCount,packetsPerInterval,"
            "intervalMs,disclosureDelay,groupSize,detectionThreshold,randomSeed,"
            "configuredFault,configuredFaultValue,sentPackets,receivedPackets,"
            "authenticatedPackets,failedPackets,missingPackets,fallbackGroupCount,"
            "verifyTimeUs,receivedAuthBytes,estimatedEnergyMicroJoule,fileSize,"
            "recoveredFileSize,recoveredFileHash,roundStatus,validSample,invalidReason\r\n"
        );
        QByteArray arrOutput;
        QJsonArray arrJsonRecords;
        if (!bJson)
        {
            arrOutput.append(strCsvHeader.toUtf8());
        }

        for (const AuthenticationRoundArchiveSummary& sumArchive
            : m_vecRoundArchives)
        {
            const AuthenticationRoundArchiveConfiguration& cfgArchive =
                sumArchive.cfgConfiguration();
            const auto* pSender = std::get_if<SenderRoundArchiveDetails>(
                &sumArchive.varDetails()
            );
            const auto* pReceiver = std::get_if<ReceiverRoundArchiveDetails>(
                &sumArchive.varDetails()
            );

            const QString strRole = pSender != nullptr
                ? QStringLiteral("SENDER") : QStringLiteral("RECEIVER");
            const QString strConfiguredFault = pSender != nullptr
                ? QString::fromStdString(pSender->strConfiguredFault())
                : QStringLiteral("NOT_DISTRIBUTED");
            const QString strConfiguredFaultValue = pSender != nullptr
                ? QString::fromStdString(pSender->strConfiguredFaultValue())
                : QString();
            const std::uint64_t u64RandomSeed = pSender != nullptr
                ? pSender->u64RandomSeed() : 0;
            const std::uint32_t u32SentPackets = pSender != nullptr
                ? pSender->u32SentPacketCount() : 0;
            const std::uint32_t u32ReceivedPackets = pReceiver != nullptr
                ? pReceiver->u32ReceivedPacketCount() : 0;
            const std::uint32_t u32AuthenticatedPackets = pReceiver != nullptr
                ? pReceiver->u32AuthenticatedPacketCount() : 0;
            const std::uint32_t u32FailedPackets = pReceiver != nullptr
                ? pReceiver->u32FailedPacketCount() : 0;
            const std::uint32_t u32MissingPackets = pReceiver != nullptr
                ? pReceiver->u32MissingPacketCount() : 0;
            const std::uint32_t u32FallbackGroupCount = pReceiver != nullptr
                ? pReceiver->u32FallbackGroupCount() : 0;
            const std::uint64_t u64VerifyTimeNanoseconds = pReceiver != nullptr
                ? pReceiver->u64VerifyTimeNanoseconds() : 0;
            const std::uint64_t u64ReceivedAuthBytes = pReceiver != nullptr
                ? pReceiver->u64ReceivedAuthBytes() : 0;
            const double dEstimatedEnergyMicroJoule = pReceiver != nullptr
                ? pReceiver->dEstimatedEnergyMicroJoule() : 0.0;
            const std::uint64_t u64FileSize = pSender != nullptr
                ? pSender->u64FileSize()
                : pReceiver->u64FileSize();
            const std::uint64_t u64RecoveredFileSize = pReceiver != nullptr
                ? pReceiver->u64RecoveredFileSize() : 0;
            const QString strRecoveredFileHash = pReceiver != nullptr
                ? QString::fromStdString(pReceiver->strRecoveredFileHash())
                : QString();

            if (bJson)
            {
                QJsonObject objRecord;
                objRecord.insert(QStringLiteral("experimentId"), QString::fromStdString(sumArchive.strExperimentId()));
                objRecord.insert(QStringLiteral("runId"), QString::fromStdString(sumArchive.strRunId()));
                objRecord.insert(QStringLiteral("timestamp"), QString::number(sumArchive.u64TimestampMilliseconds()));
                objRecord.insert(QStringLiteral("gitCommit"), QString::fromStdString(sumArchive.strGitCommit()));
                objRecord.insert(QStringLiteral("nodeId"), QString::fromStdString(sumArchive.strNodeId()));
                objRecord.insert(QStringLiteral("senderId"), QString::fromStdString(sumArchive.strSenderId()));
                objRecord.insert(QStringLiteral("chainId"), QString::number(sumArchive.u64ChainId()));
                objRecord.insert(QStringLiteral("role"), strRole);
                objRecord.insert(QStringLiteral("authMode"), strMetricMode(cfgArchive.modeAuthentication()));
                objRecord.insert(QStringLiteral("cryptoAlgorithm"), QString::fromStdString(cfgArchive.strCryptoAlgorithm()));
                objRecord.insert(QStringLiteral("payloadHash"), QString::fromStdString(cfgArchive.strPayloadHash()));
                objRecord.insert(QStringLiteral("packetCount"), static_cast<qint64>(cfgArchive.u32PacketCount()));
                objRecord.insert(QStringLiteral("packetsPerInterval"), static_cast<qint64>(cfgArchive.u32PacketsPerInterval()));
                objRecord.insert(QStringLiteral("intervalMs"), static_cast<qint64>(cfgArchive.u32IntervalMilliseconds()));
                objRecord.insert(QStringLiteral("disclosureDelay"), static_cast<qint64>(cfgArchive.u32DisclosureDelay()));
                objRecord.insert(QStringLiteral("groupSize"), static_cast<qint64>(cfgArchive.u32GroupSize()));
                objRecord.insert(QStringLiteral("detectionThreshold"), static_cast<qint64>(cfgArchive.u32DetectionThreshold()));
                objRecord.insert(QStringLiteral("randomSeed"), QString::number(u64RandomSeed));
                objRecord.insert(QStringLiteral("configuredFault"), strConfiguredFault);
                objRecord.insert(QStringLiteral("configuredFaultValue"), strConfiguredFaultValue);
                objRecord.insert(QStringLiteral("sentPackets"), static_cast<qint64>(u32SentPackets));
                objRecord.insert(QStringLiteral("receivedPackets"), static_cast<qint64>(u32ReceivedPackets));
                objRecord.insert(QStringLiteral("authenticatedPackets"), static_cast<qint64>(u32AuthenticatedPackets));
                objRecord.insert(QStringLiteral("failedPackets"), static_cast<qint64>(u32FailedPackets));
                objRecord.insert(QStringLiteral("missingPackets"), static_cast<qint64>(u32MissingPackets));
                objRecord.insert(QStringLiteral("fallbackGroupCount"), static_cast<qint64>(u32FallbackGroupCount));
                objRecord.insert(QStringLiteral("verifyTimeUs"), static_cast<double>(u64VerifyTimeNanoseconds) / 1000.0);
                objRecord.insert(QStringLiteral("receivedAuthBytes"), QString::number(u64ReceivedAuthBytes));
                objRecord.insert(QStringLiteral("estimatedEnergyMicroJoule"), dEstimatedEnergyMicroJoule);
                objRecord.insert(QStringLiteral("fileSize"), QString::number(u64FileSize));
                objRecord.insert(QStringLiteral("recoveredFileSize"), QString::number(u64RecoveredFileSize));
                objRecord.insert(QStringLiteral("recoveredFileHash"), strRecoveredFileHash);
                objRecord.insert(QStringLiteral("roundStatus"), QString::fromStdString(sumArchive.strRoundStatus()));
                objRecord.insert(QStringLiteral("validSample"), sumArchive.bValidSample());
                objRecord.insert(QStringLiteral("invalidReason"), QString::fromStdString(sumArchive.strInvalidReason()));
                arrJsonRecords.append(objRecord);
                continue;
            }

            const QStringList lstColumns{
                strCsv(QString::fromStdString(sumArchive.strExperimentId())),
                strCsv(QString::fromStdString(sumArchive.strRunId())),
                QString::number(sumArchive.u64TimestampMilliseconds()),
                strCsv(QString::fromStdString(sumArchive.strGitCommit())),
                strCsv(QString::fromStdString(sumArchive.strNodeId())),
                strCsv(QString::fromStdString(sumArchive.strSenderId())),
                QString::number(sumArchive.u64ChainId()),
                strRole,
                strMetricMode(cfgArchive.modeAuthentication()),
                strCsv(QString::fromStdString(cfgArchive.strCryptoAlgorithm())),
                strCsv(QString::fromStdString(cfgArchive.strPayloadHash())),
                QString::number(cfgArchive.u32PacketCount()),
                QString::number(cfgArchive.u32PacketsPerInterval()),
                QString::number(cfgArchive.u32IntervalMilliseconds()),
                QString::number(cfgArchive.u32DisclosureDelay()),
                QString::number(cfgArchive.u32GroupSize()),
                QString::number(cfgArchive.u32DetectionThreshold()),
                QString::number(u64RandomSeed),
                strCsv(strConfiguredFault),
                strCsv(strConfiguredFaultValue),
                QString::number(u32SentPackets),
                QString::number(u32ReceivedPackets),
                QString::number(u32AuthenticatedPackets),
                QString::number(u32FailedPackets),
                QString::number(u32MissingPackets),
                QString::number(u32FallbackGroupCount),
                QString::number(static_cast<double>(u64VerifyTimeNanoseconds) / 1000.0, 'f', 3),
                QString::number(u64ReceivedAuthBytes),
                QString::number(dEstimatedEnergyMicroJoule, 'f', 9),
                QString::number(u64FileSize),
                QString::number(u64RecoveredFileSize),
                strCsv(strRecoveredFileHash),
                strCsv(QString::fromStdString(sumArchive.strRoundStatus())),
                sumArchive.bValidSample() ? QStringLiteral("true") : QStringLiteral("false"),
                strCsv(QString::fromStdString(sumArchive.strInvalidReason()))
            };
            arrOutput.append(
                (lstColumns.join(QLatin1Char(',')) + QStringLiteral("\r\n")).toUtf8()
            );
        }

        if (bJson)
        {
            QJsonObject objRoot;
            objRoot.insert(QStringLiteral("exportedAtMs"), QString::number(
                QDateTime::currentMSecsSinceEpoch()
            ));
            objRoot.insert(QStringLiteral("roundRecords"), arrJsonRecords);
            arrOutput = QJsonDocument(objRoot).toJson(QJsonDocument::Indented);
        }

        QFile filOutput(strPath);
        if (!filOutput.open(QIODevice::WriteOnly | QIODevice::Truncate)
            || filOutput.write(arrOutput) != arrOutput.size())
        {
            QMessageBox::warning(
                m_pOwner,
                QStringLiteral("导出失败"),
                filOutput.errorString()
            );
            return;
        }

        QMessageBox::information(
            m_pOwner,
            QStringLiteral("导出完成"),
            QStringLiteral("已导出 %1 条本节点逐轮记录。")
                .arg(static_cast<qulonglong>(m_vecRoundArchives.size()))
        );
    }

    void exportSnapshots(bool bJson)
    {
        if (m_vecPackets.empty() && m_vecFailures.empty()
            && m_vecDosSummaries.empty())
        {
            QMessageBox::information(
                m_pOwner,
                QStringLiteral("导出"),
                QStringLiteral("当前没有可导出的本节点观测数据。")
            );
            return;
        }

        const QString strSuffix = bJson
            ? QStringLiteral("json")
            : QStringLiteral("csv");
        const QString strPath = QFileDialog::getSaveFileName(
            m_pOwner,
            QStringLiteral("导出本节点逐轮原始数据"),
            QStringLiteral("tesla-node-observations-%1.%2")
                .arg(
                    QDateTime::currentDateTime().toString(
                        QStringLiteral("yyyyMMdd-HHmmss")
                    ),
                    strSuffix
                ),
            bJson ? QStringLiteral("JSON (*.json)") : QStringLiteral("CSV (*.csv)")
        );
        if (strPath.isEmpty())
        {
            return;
        }

        QByteArray arrOutput;
        if (bJson)
        {
            QJsonArray arrPackets;
            for (const auto& detPacket : m_vecPackets)
            {
                QJsonObject objPacket;
                objPacket.insert(QStringLiteral("eventId"), QString::number(detPacket.u64EventId()));
                objPacket.insert(QStringLiteral("timestampMs"), QString::number(detPacket.u64TimestampMilliseconds()));
                objPacket.insert(QStringLiteral("roundId"), QString::fromStdString(detPacket.strRoundId()));
                objPacket.insert(QStringLiteral("senderId"), QString::fromStdString(detPacket.strSenderId()));
                objPacket.insert(QStringLiteral("senderIp"), QString::fromStdString(detPacket.strSenderIp()));
                objPacket.insert(QStringLiteral("actualSourceIp"), QString::fromStdString(detPacket.strActualSourceIp()));
                objPacket.insert(QStringLiteral("chainId"), QString::number(detPacket.u64ChainId()));
                objPacket.insert(QStringLiteral("intervalIndex"), static_cast<qint64>(detPacket.u32IntervalIndex()));
                objPacket.insert(QStringLiteral("packetIndex"), static_cast<qint64>(detPacket.u32PacketIndex()));
                objPacket.insert(QStringLiteral("authenticationStatus"), strPacketStatus(detPacket.statusAuthentication()));
                objPacket.insert(QStringLiteral("sourceType"), strSource(detPacket.typeSource()));
                objPacket.insert(QStringLiteral("duplicateCount"), static_cast<qint64>(detPacket.u32DuplicateCount()));
                objPacket.insert(QStringLiteral("reason"), QString::fromStdString(detPacket.strReason()));
                objPacket.insert(QStringLiteral("rawDatagramHex"), strHex(detPacket.vecRawDatagram()));
                arrPackets.append(objPacket);
            }

            QJsonArray arrFailures;
            for (const auto& detFailure : m_vecFailures)
            {
                QJsonArray arrLocated;
                for (const std::uint32_t u32Index : detFailure.vecLocatedPacketIndexes())
                {
                    arrLocated.append(static_cast<qint64>(u32Index));
                }
                QJsonObject objFailure;
                objFailure.insert(QStringLiteral("eventId"), QString::number(detFailure.u64EventId()));
                objFailure.insert(QStringLiteral("packetEventId"), QString::number(detFailure.u64PacketEventId()));
                objFailure.insert(QStringLiteral("timestampMs"), QString::number(detFailure.u64TimestampMilliseconds()));
                objFailure.insert(QStringLiteral("roundId"), QString::fromStdString(detFailure.strRoundId()));
                objFailure.insert(QStringLiteral("senderId"), QString::fromStdString(detFailure.strSenderId()));
                objFailure.insert(QStringLiteral("actualSourceIp"), QString::fromStdString(detFailure.strActualSourceIp()));
                objFailure.insert(QStringLiteral("chainId"), QString::number(detFailure.u64ChainId()));
                objFailure.insert(QStringLiteral("intervalIndex"), static_cast<qint64>(detFailure.u32IntervalIndex()));
                objFailure.insert(QStringLiteral("packetIndex"), static_cast<qint64>(detFailure.u32PacketIndex()));
                objFailure.insert(QStringLiteral("failureType"), strFailureType(detFailure.typeFailure()));
                objFailure.insert(QStringLiteral("duplicateCount"), static_cast<qint64>(detFailure.u32DuplicateCount()));
                objFailure.insert(QStringLiteral("reason"), QString::fromStdString(detFailure.strReason()));
                objFailure.insert(QStringLiteral("locatedPacketIndexes"), arrLocated);
                arrFailures.append(objFailure);
            }

            QJsonArray arrDosSummaries;
            for (const auto& detSummary : m_vecDosSummaries)
            {
                QJsonObject objSummary;
                objSummary.insert(QStringLiteral("timestampMs"), QString::number(detSummary.u64TimestampMilliseconds()));
                objSummary.insert(QStringLiteral("windowMs"), static_cast<qint64>(detSummary.u32WindowMilliseconds()));
                objSummary.insert(QStringLiteral("invalidPacketCount"), QString::number(detSummary.u64InvalidPacketCount()));
                objSummary.insert(QStringLiteral("rateLimitedDropCount"), QString::number(detSummary.u64RateLimitedDropCount()));
                objSummary.insert(QStringLiteral("legitimatePacketCount"), QString::number(detSummary.u64LegitimatePacketCount()));
                objSummary.insert(QStringLiteral("receiveQueueOverflowCount"), QString::number(detSummary.u64ReceiveQueueOverflowCount()));
                arrDosSummaries.append(objSummary);
            }

            QJsonObject objRoot;
            objRoot.insert(QStringLiteral("exportedAtMs"), QDateTime::currentMSecsSinceEpoch());
            objRoot.insert(QStringLiteral("packets"), arrPackets);
            objRoot.insert(QStringLiteral("failures"), arrFailures);
            objRoot.insert(QStringLiteral("dosSummaries"), arrDosSummaries);
            arrOutput = QJsonDocument(objRoot).toJson(QJsonDocument::Indented);
        }
        else
        {
            arrOutput.append("recordType,timestampMs,roundId,senderId,actualSourceIp,chainId,intervalIndex,packetIndex,statusOrType,duplicateCount,rawDatagramHex,details\r\n");
            for (const auto& detPacket : m_vecPackets)
            {
                const QString strLine = QStringLiteral("PACKET,%1,%2,%3,%4,%5,%6,%7,%8,%9,%10,%11\r\n")
                    .arg(detPacket.u64TimestampMilliseconds())
                    .arg(strCsv(QString::fromStdString(detPacket.strRoundId())))
                    .arg(strCsv(QString::fromStdString(detPacket.strSenderId())))
                    .arg(strCsv(QString::fromStdString(detPacket.strActualSourceIp())))
                    .arg(detPacket.u64ChainId())
                    .arg(detPacket.u32IntervalIndex())
                    .arg(detPacket.u32PacketIndex())
                    .arg(strCsv(strPacketStatus(detPacket.statusAuthentication())))
                    .arg(detPacket.u32DuplicateCount())
                    .arg(strCsv(strHex(detPacket.vecRawDatagram())))
                    .arg(strCsv(QString::fromStdString(detPacket.strReason())));
                arrOutput.append(strLine.toUtf8());
            }
            for (const auto& detFailure : m_vecFailures)
            {
                const QString strLine = QStringLiteral("FAILURE,%1,%2,%3,%4,%5,%6,%7,%8,%9,,%10\r\n")
                    .arg(detFailure.u64TimestampMilliseconds())
                    .arg(strCsv(QString::fromStdString(detFailure.strRoundId())))
                    .arg(strCsv(QString::fromStdString(detFailure.strSenderId())))
                    .arg(strCsv(QString::fromStdString(detFailure.strActualSourceIp())))
                    .arg(detFailure.u64ChainId())
                    .arg(detFailure.u32IntervalIndex())
                    .arg(detFailure.u32PacketIndex())
                    .arg(strCsv(strFailureType(detFailure.typeFailure())))
                    .arg(detFailure.u32DuplicateCount())
                    .arg(strCsv(QString::fromStdString(detFailure.strReason())));
                arrOutput.append(strLine.toUtf8());
            }
            for (const auto& detSummary : m_vecDosSummaries)
            {
                const QString strDetails = QStringLiteral(
                    "windowMs=%1; invalid=%2; limited=%3; legitimate=%4; overflow=%5"
                )
                    .arg(detSummary.u32WindowMilliseconds())
                    .arg(detSummary.u64InvalidPacketCount())
                    .arg(detSummary.u64RateLimitedDropCount())
                    .arg(detSummary.u64LegitimatePacketCount())
                    .arg(detSummary.u64ReceiveQueueOverflowCount());
                const QString strLine = QStringLiteral("DOS_SUMMARY,%1,,,,,,,DOS_SUMMARY,,,%2\r\n")
                    .arg(detSummary.u64TimestampMilliseconds())
                    .arg(strCsv(strDetails));
                arrOutput.append(strLine.toUtf8());
            }
        }

        QFile filOutput(strPath);
        if (!filOutput.open(QIODevice::WriteOnly | QIODevice::Truncate)
            || filOutput.write(arrOutput) != arrOutput.size())
        {
            QMessageBox::warning(
                m_pOwner,
                QStringLiteral("导出失败"),
                filOutput.errorString()
            );
            return;
        }

        QMessageBox::information(
            m_pOwner,
            QStringLiteral("导出完成"),
            QStringLiteral("本节点观测原始数据已导出。")
        );
    }

    void createPages()
    {
        QVBoxLayout* pRootLayout = new QVBoxLayout(m_pOwner);
        QWidget* pPacketPage = new QWidget(m_pOwner);
        QVBoxLayout* pPacketLayout = new QVBoxLayout(pPacketPage);
        QHBoxLayout* pQuickFilterLayout = new QHBoxLayout();
        m_pQuickButtons = new QButtonGroup(m_pOwner);
        m_pQuickButtons->setExclusive(true);
        static const std::array<std::pair<const char*, QuickFilter>, 2> FILTERS{
            std::pair{"全部", QuickFilter::All},
            std::pair{"仅看异常", QuickFilter::Abnormal}
        };
        for (std::size_t nIndex = 0; nIndex < FILTERS.size(); ++nIndex)
        {
            QPushButton* pButton = new QPushButton(
                QString::fromUtf8(FILTERS[nIndex].first),
                pPacketPage
            );
            pButton->setCheckable(true);
            pButton->setMinimumWidth(120);
            pButton->setStyleSheet(QStringLiteral(
                "QPushButton {"
                "  min-height: 28px; padding: 2px 16px;"
                "  border: 1px solid #cbd5e1; border-radius: 5px;"
                "  background: #ffffff; color: #334155;"
                "}"
                "QPushButton:hover {"
                "  border-color: #60a5fa; background: #eff6ff;"
                "}"
                "QPushButton:checked {"
                "  border-color: #2563eb; background: #2563eb; color: #ffffff;"
                "}"
            ));
            m_pQuickButtons->addButton(pButton, static_cast<int>(nIndex));
            m_vecQuickButtons.push_back(pButton);
            pQuickFilterLayout->addWidget(pButton);
        }
        pQuickFilterLayout->addSpacing(12);
        pQuickFilterLayout->addWidget(
            new QLabel(QStringLiteral("异常类型"), pPacketPage)
        );
        m_pAbnormalTypeCombo->setFixedWidth(190);
        pQuickFilterLayout->addWidget(m_pAbnormalTypeCombo);
        pQuickFilterLayout->addStretch();
        m_vecQuickButtons.front()->setChecked(true);
        pPacketLayout->addLayout(pQuickFilterLayout);

        QHBoxLayout* pQueryLayout = new QHBoxLayout();
        pQueryLayout->setSpacing(8);
        pQueryLayout->addWidget(new QLabel(QStringLiteral("Sender"), pPacketPage));
        m_pSenderEdit->setFixedWidth(180);
        pQueryLayout->addWidget(m_pSenderEdit);
        pQueryLayout->addSpacing(20);
        pQueryLayout->addWidget(new QLabel(QStringLiteral("报文编号"), pPacketPage));
        m_pPacketEdit->setFixedWidth(150);
        pQueryLayout->addWidget(m_pPacketEdit);
        QPushButton* pQueryButton = new QPushButton(QStringLiteral("查询"), pPacketPage);
        QPushButton* pClearButton = new QPushButton(QStringLiteral("清除筛选"), pPacketPage);
        pQueryButton->setFixedWidth(72);
        pClearButton->setFixedWidth(96);
        pQueryLayout->addSpacing(12);
        pQueryLayout->addWidget(pQueryButton);
        pQueryLayout->addWidget(pClearButton);
        pQueryLayout->addStretch();
        pPacketLayout->addLayout(pQueryLayout);
        pPacketLayout->addWidget(m_pDosLabel);

        QSplitter* pSplitter = new QSplitter(Qt::Vertical, pPacketPage);
        pSplitter->addWidget(m_pPacketTable);
        pSplitter->addWidget(m_pDetailEdit);
        pSplitter->setStretchFactor(0, 3);
        pSplitter->setStretchFactor(1, 2);
        pPacketLayout->addWidget(pSplitter, 1);
        pRootLayout->addWidget(pPacketPage);

        m_pPacketTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_pPacketTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_pPacketTable->setSortingEnabled(true);
        m_pPacketTable->horizontalHeader()->setSectionResizeMode(
            QHeaderView::Stretch
        );

        QObject::connect(pQueryButton, &QPushButton::clicked, m_pOwner, [this]()
        {
            applyQuery();
        });
        QObject::connect(pClearButton, &QPushButton::clicked, m_pOwner, [this]()
        {
            clearFilters();
        });
    }

    void connectActions()
    {
        QObject::connect(
            m_pQuickButtons,
            &QButtonGroup::idClicked,
            m_pOwner,
            [this](int nId)
            {
                const bool bOnlyAbnormal = nId == 1;
                m_pAbnormalTypeCombo->setEnabled(bOnlyAbnormal);
                m_pProxyModel->setQuickFilter(
                    bOnlyAbnormal
                        ? fltSelectedAbnormalFilter()
                        : QuickFilter::All
                );
            }
        );
        QObject::connect(
            m_pAbnormalTypeCombo,
            &QComboBox::currentIndexChanged,
            m_pOwner,
            [this]()
            {
                m_vecQuickButtons[1]->setChecked(true);
                m_pAbnormalTypeCombo->setEnabled(true);
                m_pProxyModel->setQuickFilter(fltSelectedAbnormalFilter());
            }
        );
        QObject::connect(
            m_pPacketTable->selectionModel(),
            &QItemSelectionModel::currentRowChanged,
            m_pOwner,
            [this](const QModelIndex& idxCurrent)
            {
                const QModelIndex idxSource = m_pProxyModel->mapToSource(
                    idxCurrent
                );
                const PacketFailureControlDetails* pStandaloneFailure
                    = m_pPacketModel->pStandaloneFailure(idxSource.row());
                if (pStandaloneFailure != nullptr)
                {
                    m_pDetailEdit->setPlainText(
                        strFailureDetails(*pStandaloneFailure)
                    );
                    return;
                }

                const PacketObservationControlDetails* pPacket
                    = m_pPacketModel->pPacket(idxSource.row());
                if (pPacket == nullptr)
                {
                    m_pDetailEdit->clear();
                    return;
                }

                QString strDetails = strPacketDetails(*pPacket);
                for (const PacketFailureControlDetails& detFailure
                    : m_vecFailures)
                {
                    if (detFailure.u64PacketEventId() == pPacket->u64EventId())
                    {
                        strDetails += QStringLiteral("\n\n--- 关联异常 ---\n")
                            + strFailureDetails(detFailure);
                    }
                }
                m_pDetailEdit->setPlainText(strDetails);
            }
        );
    }

    void applyQuery()
    {
        m_pProxyModel->setQuery(
            m_pSenderEdit->text(),
            m_pPacketEdit->text()
        );
        refreshQuickButtonCounts();
    }

    QuickFilter fltSelectedAbnormalFilter() const noexcept
    {
        switch (m_pAbnormalTypeCombo->currentIndex())
        {
        case 1:
            return QuickFilter::AuthenticationFailed;
        case 2:
            return QuickFilter::Missing;
        default:
            return QuickFilter::Abnormal;
        }
    }

    void clearFilters()
    {
        for (QLineEdit* pEdit : {
                m_pSenderEdit,
                m_pPacketEdit
            })
        {
            pEdit->clear();
        }
        m_pAbnormalTypeCombo->blockSignals(true);
        m_pAbnormalTypeCombo->setCurrentIndex(0);
        m_pAbnormalTypeCombo->blockSignals(false);
        m_pAbnormalTypeCombo->setEnabled(false);
        m_vecQuickButtons.front()->setChecked(true);
        m_pProxyModel->setQuickFilter(QuickFilter::All);
        applyQuery();
    }

    void refreshQuickButtonCounts()
    {
        std::array<int, 4> arrCounts{};
        arrCounts[0] = m_pPacketModel->rowCount();
        for (const PacketFailureControlDetails& detFailure : m_vecFailures)
        {
            if ((!m_pSenderEdit->text().trimmed().isEmpty()
                    && QString::fromStdString(detFailure.strSenderId())
                        != m_pSenderEdit->text().trimmed())
                || (!m_pPacketEdit->text().trimmed().isEmpty()
                    && QString::number(detFailure.u32PacketIndex())
                        != m_pPacketEdit->text().trimmed()))
            {
                continue;
            }

            if (bIsMissingFailure(detFailure.typeFailure()))
            {
                ++arrCounts[3];
            }
            else
            {
                ++arrCounts[2];
            }
            ++arrCounts[1];
        }
        static const std::array<const char*, 4> NAMES{
            "全部", "仅看异常", "MAC/分组校验失败", "丢包"
        };
        for (std::size_t nIndex = 0; nIndex < m_vecQuickButtons.size(); ++nIndex)
        {
            m_vecQuickButtons[nIndex]->setText(
                QStringLiteral("%1(%2)")
                    .arg(QString::fromUtf8(NAMES[nIndex]))
                    .arg(arrCounts[nIndex])
            );
        }
        m_pAbnormalTypeCombo->setItemText(
            0,
            QStringLiteral("全部异常(%1)").arg(arrCounts[1])
        );
        m_pAbnormalTypeCombo->setItemText(
            1,
            QStringLiteral("MAC/分组校验失败(%1)").arg(arrCounts[2])
        );
        m_pAbnormalTypeCombo->setItemText(
            2,
            QStringLiteral("丢包(%1)").arg(arrCounts[3])
        );
    }

    AuthenticationMonitorWidget* m_pOwner;
    PacketTableModel*             m_pPacketModel;
    PacketFilterProxyModel*       m_pProxyModel;
    QTableView*                   m_pPacketTable;
    QTextEdit*                    m_pDetailEdit;
    QLineEdit*                    m_pSenderEdit;
    QLineEdit*                    m_pPacketEdit;
    QComboBox*                    m_pAbnormalTypeCombo;
    QLabel*                       m_pDosLabel;
    QButtonGroup*                 m_pQuickButtons{nullptr};
    std::vector<QPushButton*> m_vecQuickButtons;
    std::vector<PacketObservationControlDetails> m_vecPackets;
    std::vector<PacketFailureControlDetails> m_vecFailures;
    std::vector<DosSummaryControlDetails> m_vecDosSummaries;
    std::vector<AuthenticationRoundArchiveSummary> m_vecRoundArchives;
};

AuthenticationMonitorWidget::AuthenticationMonitorWidget(QWidget* pParent)
    : QWidget(pParent),
      m_pImpl(new Impl(this))
{
}

AuthenticationMonitorWidget::~AuthenticationMonitorWidget()
{
    delete m_pImpl;
}

void AuthenticationMonitorWidget::setSnapshots(
    std::vector<PacketObservationControlDetails> vecPackets,
    std::vector<PacketFailureControlDetails> vecFailures,
    std::vector<DosSummaryControlDetails> vecDosSummaries
)
{
    m_pImpl->setSnapshots(
        std::move(vecPackets),
        std::move(vecFailures),
        std::move(vecDosSummaries)
    );
}

void AuthenticationMonitorWidget::setMetricSnapshots(
    std::vector<metrics::AuthenticationMetricRecord> vecMetrics
)
{
    m_pImpl->setMetricSnapshots(std::move(vecMetrics));
}
}
