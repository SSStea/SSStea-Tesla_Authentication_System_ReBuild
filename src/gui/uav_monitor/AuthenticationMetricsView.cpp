#include "AuthenticationMetricsView.h"

#include <QChart>
#include <QChartView>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineSeries>
#include <QMessageBox>
#include <QPainter>
#include <QPushButton>
#include <QString>
#include <QValueAxis>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <variant>

namespace
{
constexpr std::size_t MAX_CHART_POINT_COUNT = 2000;

QString strCsv(const QString& strValue)
{
    QString strEscaped = strValue;
    strEscaped.replace(QLatin1Char('"'), QStringLiteral("\"\""));
    return QLatin1Char('"') + strEscaped + QLatin1Char('"');
}

QString strMetricMode(tesla::metrics::AuthenticationMetricMode modeAuthentication)
{
    return modeAuthentication == tesla::metrics::AuthenticationMetricMode::Native
        ? QStringLiteral("NATIVE")
        : QStringLiteral("IMPROVED");
}

QString strMetricPath(tesla::metrics::VerificationMetricPath pathVerification)
{
    using tesla::metrics::VerificationMetricPath;
    switch (pathVerification)
    {
    case VerificationMetricPath::NativePacketVerify:
        return QStringLiteral("NATIVE_PACKET_VERIFY");
    case VerificationMetricPath::FastGroupPass:
        return QStringLiteral("FAST_GROUP_PASS");
    case VerificationMetricPath::KsRsFallback:
        return QStringLiteral("KS_RS_FALLBACK");
    case VerificationMetricPath::IncompleteGroupTags:
        return QStringLiteral("INCOMPLETE_GROUP_TAGS");
    }

    return QStringLiteral("UNKNOWN");
}

QString strHardwareStatus(tesla::metrics::HardwareCounterStatus statusCounters)
{
    using tesla::metrics::HardwareCounterStatus;
    switch (statusCounters)
    {
    case HardwareCounterStatus::Supported:
        return QStringLiteral("设备支持");
    case HardwareCounterStatus::NotSupported:
        return QStringLiteral("设备不支持");
    case HardwareCounterStatus::PermissionDenied:
        return QStringLiteral("无读取权限");
    case HardwareCounterStatus::ReadFailed:
        return QStringLiteral("读取失败");
    }

    return QStringLiteral("未知");
}

QWidget* pCreateChartPage(
    QWidget* pParent,
    const QString& strTitle,
    const QString& strHint,
    QLabel*& pSummary,
    QLabel*& pSecondarySummary,
    QChart*& pChart
)
{
    QWidget* pPage = new QWidget(pParent);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    QLabel* pTitle = new QLabel(strTitle, pPage);
    pTitle->setObjectName(QStringLiteral("sectionTitleLabel"));
    QLabel* pHint = new QLabel(strHint, pPage);
    pHint->setWordWrap(true);
    pHint->setObjectName(QStringLiteral("hintLabel"));
    pSummary = new QLabel(QStringLiteral("尚无真实认证指标"), pPage);
    pSummary->setObjectName(QStringLiteral("stateValue"));
    pSecondarySummary = new QLabel(pPage);
    pSecondarySummary->setObjectName(QStringLiteral("hintLabel"));
    pChart = new QChart();
    pChart->setAnimationOptions(QChart::NoAnimation);
    pChart->legend()->setVisible(true);
    QChartView* pChartView = new QChartView(pChart, pPage);
    pChartView->setRenderHint(QPainter::Antialiasing);

    pLayout->addWidget(pTitle);
    pLayout->addWidget(pHint);
    pLayout->addWidget(pSummary);
    pLayout->addWidget(pSecondarySummary);
    pLayout->addWidget(pChartView, 1);
    return pPage;
}
}

AuthenticationMetricsView::AuthenticationMetricsView(QWidget* pParent)
    : m_pComputationPage(nullptr),
      m_pEnergyPage(nullptr),
      m_pComputationSummary(nullptr),
      m_pHardwareSummary(nullptr),
      m_pEnergySummary(nullptr),
      m_pNativeVerifySeries(new QLineSeries()),
      m_pFastVerifySeries(new QLineSeries()),
      m_pNativeEnergySeries(new QLineSeries()),
      m_pFastEnergySeries(new QLineSeries()),
      m_pComputationXAxis(new QValueAxis()),
      m_pComputationYAxis(new QValueAxis()),
      m_pEnergyXAxis(new QValueAxis()),
      m_pEnergyYAxis(new QValueAxis())
{
    QChart* pComputationChart = nullptr;
    m_pComputationPage = pCreateChartPage(
        pParent,
        QStringLiteral("计算开销"),
        QStringLiteral(
            "每个点表示一轮正常认证的累计验证耗时；"
            "TESLA与S-TESLA分别从第一轮开始计数。"
        ),
        m_pComputationSummary,
        m_pHardwareSummary,
        pComputationChart
    );
    configureSeries(m_pNativeVerifySeries, QStringLiteral("TESLA"));
    configureSeries(m_pFastVerifySeries, QStringLiteral("S-TESLA"));
    pComputationChart->addAxis(m_pComputationXAxis, Qt::AlignBottom);
    pComputationChart->addAxis(m_pComputationYAxis, Qt::AlignLeft);
    for (QLineSeries* pSeries : {
            m_pNativeVerifySeries,
            m_pFastVerifySeries
        })
    {
        pComputationChart->addSeries(pSeries);
        pSeries->attachAxis(m_pComputationXAxis);
        pSeries->attachAxis(m_pComputationYAxis);
    }
    m_pComputationXAxis->setTitleText(QStringLiteral("模式内认证轮次"));
    m_pComputationYAxis->setTitleText(QStringLiteral("本轮累计验证耗时 (μs)"));
    m_pComputationXAxis->setLabelFormat(QStringLiteral("%.0f"));

    QChart* pEnergyChart = nullptr;
    QLabel* pEnergyModel = nullptr;
    m_pEnergyPage = pCreateChartPage(
        pParent,
        QStringLiteral("估算验证能耗"),
        QStringLiteral(
            "每个点表示一轮正常认证的估算能耗；"
            "TESLA与S-TESLA分别从第一轮开始计数。"
        ),
        m_pEnergySummary,
        pEnergyModel,
        pEnergyChart
    );
    pEnergyModel->setText(QStringLiteral(
        "固定模型：0.181 μJ/μs × 验证耗时 + 0.038504 μJ/B × 认证字段字节数"
    ));
    configureSeries(m_pNativeEnergySeries, QStringLiteral("TESLA"));
    configureSeries(m_pFastEnergySeries, QStringLiteral("S-TESLA"));
    pEnergyChart->addAxis(m_pEnergyXAxis, Qt::AlignBottom);
    pEnergyChart->addAxis(m_pEnergyYAxis, Qt::AlignLeft);
    for (QLineSeries* pSeries : {
            m_pNativeEnergySeries,
            m_pFastEnergySeries
        })
    {
        pEnergyChart->addSeries(pSeries);
        pSeries->attachAxis(m_pEnergyXAxis);
        pSeries->attachAxis(m_pEnergyYAxis);
    }
    m_pEnergyXAxis->setTitleText(QStringLiteral("模式内认证轮次"));
    m_pEnergyYAxis->setTitleText(QStringLiteral("估算能耗 (mJ)"));
    m_pEnergyXAxis->setLabelFormat(QStringLiteral("%.0f"));

    updateAxes(m_pComputationXAxis, m_pComputationYAxis, 1.0, 1.0);
    updateAxes(m_pEnergyXAxis, m_pEnergyYAxis, 1.0, 1.0);

    // 两个页面共用同一份完整记录，按钮仅提供不同的导出入口。
    for (QWidget* pPage : {m_pComputationPage, m_pEnergyPage})
    {
        QHBoxLayout* pExportLayout = new QHBoxLayout();
        QPushButton* pCsvButton = new QPushButton(
            QStringLiteral("导出指标CSV"),
            pPage
        );
        QPushButton* pJsonButton = new QPushButton(
            QStringLiteral("导出指标JSON"),
            pPage
        );
        pExportLayout->addWidget(pCsvButton);
        pExportLayout->addWidget(pJsonButton);
        pExportLayout->addStretch(1);
        qobject_cast<QVBoxLayout*>(pPage->layout())->insertLayout(4, pExportLayout);

        QObject::connect(
            pCsvButton,
            &QPushButton::clicked,
            pPage,
            [this]()
            {
                exportRecords(false);
            }
        );
        QObject::connect(
            pJsonButton,
            &QPushButton::clicked,
            pPage,
            [this]()
            {
                exportRecords(true);
            }
        );
    }
}

QWidget* AuthenticationMetricsView::pComputationPage() const noexcept
{
    return m_pComputationPage;
}

QWidget* AuthenticationMetricsView::pEnergyPage() const noexcept
{
    return m_pEnergyPage;
}

void AuthenticationMetricsView::setRecords(
    const std::vector<tesla::metrics::AuthenticationMetricRecord>& vecRecords
)
{
    using namespace tesla::metrics;
    m_vecRecords = vecRecords;

    for (QLineSeries* pSeries : {
            m_pNativeVerifySeries,
            m_pFastVerifySeries,
            m_pNativeEnergySeries,
            m_pFastEnergySeries
        })
    {
        pSeries->clear();
    }

    const auto fnEligibleRoundCount = [&vecRecords](
        AuthenticationMetricMode modeAuthentication
    )
    {
        return static_cast<std::size_t>(std::count_if(
            vecRecords.begin(),
            vecRecords.end(),
            [modeAuthentication](const AuthenticationMetricRecord& varRecord)
            {
                const auto* pEnergy = std::get_if<EstimatedEnergyMetricSummary>(
                    &varRecord
                );
                return pEnergy != nullptr
                    && pEnergy->bNormalComparisonEligible()
                    && pEnergy->modeAuthentication() == modeAuthentication;
            }
        ));
    };

    const std::size_t nNativeRoundCount = fnEligibleRoundCount(
        AuthenticationMetricMode::Native
    );
    const std::size_t nImprovedRoundCount = fnEligibleRoundCount(
        AuthenticationMetricMode::Improved
    );
    const std::size_t nNativeRoundSkip = nNativeRoundCount > MAX_CHART_POINT_COUNT
        ? nNativeRoundCount - MAX_CHART_POINT_COUNT
        : 0;
    const std::size_t nImprovedRoundSkip =
        nImprovedRoundCount > MAX_CHART_POINT_COUNT
        ? nImprovedRoundCount - MAX_CHART_POINT_COUNT
        : 0;

    std::size_t nNativeRoundSeen = 0;
    std::size_t nImprovedRoundSeen = 0;
    qreal dNativeRoundX = 0.0;
    qreal dImprovedRoundX = 0.0;
    qreal dMaximumVerifyTime = 0.0;
    qreal dMaximumEnergy = 0.0;
    const EstimatedEnergyMetricSummary* pLatestRound = nullptr;

    for (const AuthenticationMetricRecord& varRecord : vecRecords)
    {
        const auto* pEnergy = std::get_if<EstimatedEnergyMetricSummary>(
            &varRecord
        );
        if (pEnergy == nullptr || !pEnergy->bNormalComparisonEligible())
        {
            continue;
        }

        const bool bNative = pEnergy->modeAuthentication()
            == AuthenticationMetricMode::Native;
        std::size_t& nRoundSeen = bNative
            ? nNativeRoundSeen
            : nImprovedRoundSeen;
        const std::size_t nRoundSkip = bNative
            ? nNativeRoundSkip
            : nImprovedRoundSkip;
        ++nRoundSeen;
        if (nRoundSeen <= nRoundSkip)
        {
            continue;
        }

        qreal& dRoundX = bNative ? dNativeRoundX : dImprovedRoundX;
        QLineSeries* pVerifySeries = bNative
            ? m_pNativeVerifySeries
            : m_pFastVerifySeries;
        QLineSeries* pEnergySeries = bNative
            ? m_pNativeEnergySeries
            : m_pFastEnergySeries;

        ++dRoundX;
        const qreal dVerifyTimeMicroseconds = static_cast<qreal>(
            pEnergy->u64VerifyTimeNanoseconds()
        ) / 1000.0;
        const qreal dEnergyMilliJoule = pEnergy->dEstimatedEnergyMilliJoule();

        pVerifySeries->append(dRoundX, dVerifyTimeMicroseconds);
        pEnergySeries->append(dRoundX, dEnergyMilliJoule);
        dMaximumVerifyTime = std::max(
            dMaximumVerifyTime,
            dVerifyTimeMicroseconds
        );
        dMaximumEnergy = std::max(dMaximumEnergy, dEnergyMilliJoule);
        pLatestRound = pEnergy;
    }

    if (pLatestRound == nullptr)
    {
        m_pComputationSummary->setText(QStringLiteral("尚无正常认证轮次"));
        m_pHardwareSummary->setText(QStringLiteral(
            "逐次硬件计数保留在原始指标导出记录中"
        ));
        m_pEnergySummary->setText(QStringLiteral("尚无正常轮次估算能耗"));
    }
    else
    {
        const QString strMode = pLatestRound->modeAuthentication()
            == AuthenticationMetricMode::Native
            ? QStringLiteral("TESLA")
            : QStringLiteral("S-TESLA");
        const double dVerifyTimeMicroseconds = static_cast<double>(
            pLatestRound->u64VerifyTimeNanoseconds()
        ) / 1000.0;
        const double dAveragePacketVerifyTimeMicroseconds =
            dVerifyTimeMicroseconds
            / static_cast<double>(pLatestRound->u32PacketCount());

        m_pComputationSummary->setText(
            QStringLiteral("最新正常%1轮次：累计验证耗时=%2 μs；平均每包=%3 μs")
                .arg(strMode)
                .arg(dVerifyTimeMicroseconds, 0, 'f', 3)
                .arg(
                    dAveragePacketVerifyTimeMicroseconds,
                    0,
                    'f',
                    3
                )
        );
        m_pHardwareSummary->setText(QStringLiteral(
            "逐次硬件计数保留在原始指标导出记录中；图表按轮次汇总"
        ));
        m_pEnergySummary->setText(
            QStringLiteral(
                "最新正常%1轮次：估算能耗=%2 mJ；平均每包=%3 μJ；"
                "验证耗时=%4 μs；接收算法字段=%5B"
            )
                .arg(strMode)
                .arg(pLatestRound->dEstimatedEnergyMilliJoule(), 0, 'f', 6)
                .arg(pLatestRound->dAveragePacketEnergyMicroJoule(), 0, 'f', 6)
                .arg(dVerifyTimeMicroseconds, 0, 'f', 3)
                .arg(pLatestRound->u64ReceivedAuthBytes())
        );
    }

    const qreal dMaximumRoundX = std::max(dNativeRoundX, dImprovedRoundX);
    updateAxes(
        m_pComputationXAxis,
        m_pComputationYAxis,
        dMaximumRoundX,
        dMaximumVerifyTime
    );
    updateAxes(
        m_pEnergyXAxis,
        m_pEnergyYAxis,
        dMaximumRoundX,
        dMaximumEnergy
    );
}

void AuthenticationMetricsView::exportRecords(bool bJson) const
{
    using namespace tesla::metrics;
    if (m_vecRecords.empty())
    {
        QMessageBox::information(
            m_pComputationPage,
            QStringLiteral("导出指标"),
            QStringLiteral("当前没有可导出的认证指标记录。")
        );
        return;
    }

    const QString strExtension = bJson
        ? QStringLiteral("json")
        : QStringLiteral("csv");
    const QString strFilePath = QFileDialog::getSaveFileName(
        m_pComputationPage,
        QStringLiteral("导出认证指标原始记录"),
        QStringLiteral("tesla_metrics_%1.%2")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")))
            .arg(strExtension),
        bJson
            ? QStringLiteral("JSON 文件 (*.json)")
            : QStringLiteral("CSV 文件 (*.csv)")
    );
    if (strFilePath.isEmpty())
    {
        return;
    }

    QJsonArray arrRecords;
    QString strContent = QStringLiteral(
        "record_type,timestamp_ms,round_id,sender_id,chain_id,mode,path,"
        "packet_count,duration_ns,cpu_cycles,cache_references,cache_misses,"
        "received_auth_bytes,estimated_energy_uj,comparison_eligible,"
        "message_bytes,key_bytes,mac_bytes,tau_bytes,fast_group_tag_bytes,details\r\n"
    );

    for (const AuthenticationMetricRecord& varRecord : m_vecRecords)
    {
        QJsonObject objRecord;
        QStringList lstColumns;
        lstColumns.reserve(21);

        auto appendCommon = [&lstColumns](
            const QString& strType,
            std::uint64_t u64Timestamp,
            const std::string& strRoundId,
            const std::string& strSenderId,
            std::uint64_t u64ChainId,
            const QString& strMode
        )
        {
            lstColumns << strType
                       << QString::number(u64Timestamp)
                       << strCsv(QString::fromStdString(strRoundId))
                       << strCsv(QString::fromStdString(strSenderId))
                       << QString::number(u64ChainId)
                       << strMode;
        };

        if (const auto* pSample = std::get_if<VerificationMetricSample>(&varRecord))
        {
            const HardwarePerformanceCounters& ctrHardware =
                pSample->mstPerformance().ctrHardware();
            const QString strPath = strMetricPath(pSample->pathVerification());
            QString strDetails;
            if (const auto* pNative = std::get_if<NativeVerificationMetricDetails>(
                    &pSample->varDetails()
                ))
            {
                strDetails = QStringLiteral("interval=%1;packet=%2")
                    .arg(pNative->u32IntervalIndex())
                    .arg(pNative->u32PacketIndex());
            }
            else
            {
                const auto& detImproved = std::get<ImprovedVerificationMetricDetails>(
                    pSample->varDetails()
                );
                strDetails = QStringLiteral("group=%1;first=%2;last=%3")
                    .arg(detImproved.u32GroupIndex())
                    .arg(detImproved.u32FirstPacketIndex())
                    .arg(detImproved.u32LastPacketIndex());
            }

            objRecord.insert(QStringLiteral("recordType"), QStringLiteral("VERIFICATION"));
            objRecord.insert(QStringLiteral("eventId"), QString::number(pSample->u64EventId()));
            objRecord.insert(QStringLiteral("timestampMs"), QString::number(pSample->u64TimestampMilliseconds()));
            objRecord.insert(QStringLiteral("roundId"), QString::fromStdString(pSample->strRoundId()));
            objRecord.insert(QStringLiteral("senderId"), QString::fromStdString(pSample->strSenderId()));
            objRecord.insert(QStringLiteral("chainId"), QString::number(pSample->u64ChainId()));
            objRecord.insert(QStringLiteral("mode"), strMetricMode(pSample->modeAuthentication()));
            objRecord.insert(QStringLiteral("path"), strPath);
            objRecord.insert(QStringLiteral("packetCount"), static_cast<int>(pSample->u32PacketCount()));
            objRecord.insert(QStringLiteral("durationNs"), QString::number(pSample->mstPerformance().u64DurationNanoseconds()));
            objRecord.insert(QStringLiteral("hardwareStatus"), strHardwareStatus(ctrHardware.statusCounters()));
            objRecord.insert(QStringLiteral("cpuCycles"), QString::number(ctrHardware.u64CpuCycles()));
            objRecord.insert(QStringLiteral("cacheReferences"), QString::number(ctrHardware.u64CacheReferences()));
            objRecord.insert(QStringLiteral("cacheMisses"), QString::number(ctrHardware.u64CacheMisses()));
            objRecord.insert(QStringLiteral("details"), strDetails);

            appendCommon(
                QStringLiteral("VERIFICATION"),
                pSample->u64TimestampMilliseconds(),
                pSample->strRoundId(),
                pSample->strSenderId(),
                pSample->u64ChainId(),
                strMetricMode(pSample->modeAuthentication())
            );
            lstColumns << strPath
                       << QString::number(pSample->u32PacketCount())
                       << QString::number(pSample->mstPerformance().u64DurationNanoseconds())
                       << QString::number(ctrHardware.u64CpuCycles())
                       << QString::number(ctrHardware.u64CacheReferences())
                       << QString::number(ctrHardware.u64CacheMisses())
                       << QString() << QString() << QString()
                       << QString() << QString() << QString() << QString() << QString()
                       << strCsv(strDetails);
        }
        else if (const auto* pEnergy = std::get_if<EstimatedEnergyMetricSummary>(&varRecord))
        {
            QString strDetails;
            if (const auto* pNative = std::get_if<NativeRoundMetricDetails>(
                    &pEnergy->varDetails()
                ))
            {
                strDetails = QStringLiteral("verified=%1")
                    .arg(pNative->u32VerifiedPacketCount());
            }
            else
            {
                const auto& detImproved = std::get<ImprovedRoundMetricDetails>(
                    pEnergy->varDetails()
                );
                strDetails = QStringLiteral("fast=%1;fallback=%2;incomplete=%3")
                    .arg(detImproved.u32FastGroupCount())
                    .arg(detImproved.u32FallbackGroupCount())
                    .arg(detImproved.u32IncompleteGroupCount());
            }

            objRecord.insert(QStringLiteral("recordType"), QStringLiteral("ENERGY_ESTIMATE"));
            objRecord.insert(QStringLiteral("timestampMs"), QString::number(pEnergy->u64TimestampMilliseconds()));
            objRecord.insert(QStringLiteral("roundId"), QString::fromStdString(pEnergy->strRoundId()));
            objRecord.insert(QStringLiteral("senderId"), QString::fromStdString(pEnergy->strSenderId()));
            objRecord.insert(QStringLiteral("chainId"), QString::number(pEnergy->u64ChainId()));
            objRecord.insert(QStringLiteral("mode"), strMetricMode(pEnergy->modeAuthentication()));
            objRecord.insert(QStringLiteral("packetCount"), static_cast<int>(pEnergy->u32PacketCount()));
            objRecord.insert(QStringLiteral("verifyTimeNs"), QString::number(pEnergy->u64VerifyTimeNanoseconds()));
            objRecord.insert(QStringLiteral("receivedAuthBytes"), QString::number(pEnergy->u64ReceivedAuthBytes()));
            objRecord.insert(QStringLiteral("estimatedEnergyMicroJoule"), pEnergy->dEstimatedEnergyMicroJoule());
            objRecord.insert(QStringLiteral("normalComparisonEligible"), pEnergy->bNormalComparisonEligible());
            objRecord.insert(QStringLiteral("details"), strDetails);

            appendCommon(
                QStringLiteral("ENERGY_ESTIMATE"),
                pEnergy->u64TimestampMilliseconds(),
                pEnergy->strRoundId(),
                pEnergy->strSenderId(),
                pEnergy->u64ChainId(),
                strMetricMode(pEnergy->modeAuthentication())
            );
            lstColumns << QString()
                       << QString::number(pEnergy->u32PacketCount())
                       << QString::number(pEnergy->u64VerifyTimeNanoseconds())
                       << QString() << QString() << QString()
                       << QString::number(pEnergy->u64ReceivedAuthBytes())
                       << QString::number(pEnergy->dEstimatedEnergyMicroJoule(), 'f', 9)
                       << (pEnergy->bNormalComparisonEligible() ? QStringLiteral("true") : QStringLiteral("false"))
                       << QString() << QString() << QString() << QString() << QString()
                       << strCsv(strDetails);
        }
        else if (const auto* pCost = std::get_if<
                CommunicationCostMetricSummary
            >(&varRecord))
        {
            const CommunicationCostMetricSummary& sumCost = *pCost;
            std::uint64_t u64MessageBytes = 0;
            std::uint64_t u64KeyBytes = 0;
            std::uint64_t u64MacBytes = 0;
            std::uint64_t u64TauBytes = 0;
            std::uint64_t u64FastGroupTagBytes = 0;
            if (const auto* pNative = std::get_if<NativeCommunicationCostDetails>(
                    &sumCost.varDetails()
                ))
            {
                u64MessageBytes = pNative->u64MessageBytes();
                u64KeyBytes = pNative->u64KeyBytes();
                u64MacBytes = pNative->u64MacBytes();
            }
            else
            {
                const auto& detImproved = std::get<ImprovedCommunicationCostDetails>(
                    sumCost.varDetails()
                );
                u64MessageBytes = detImproved.u64MessageBytes();
                u64KeyBytes = detImproved.u64KeyBytes();
                u64TauBytes = detImproved.u64TauBytes();
                u64FastGroupTagBytes = detImproved.u64FastGroupTagBytes();
            }

            objRecord.insert(QStringLiteral("recordType"), QStringLiteral("COMMUNICATION_COST"));
            objRecord.insert(QStringLiteral("timestampMs"), QString::number(sumCost.u64TimestampMilliseconds()));
            objRecord.insert(QStringLiteral("roundId"), QString::fromStdString(sumCost.strRoundId()));
            objRecord.insert(QStringLiteral("senderId"), QString::fromStdString(sumCost.strSenderId()));
            objRecord.insert(QStringLiteral("chainId"), QString::number(sumCost.u64ChainId()));
            objRecord.insert(QStringLiteral("mode"), strMetricMode(sumCost.modeAuthentication()));
            objRecord.insert(QStringLiteral("messageBytes"), QString::number(u64MessageBytes));
            objRecord.insert(QStringLiteral("keyBytes"), QString::number(u64KeyBytes));
            objRecord.insert(QStringLiteral("macBytes"), QString::number(u64MacBytes));
            objRecord.insert(QStringLiteral("tauBytes"), QString::number(u64TauBytes));
            objRecord.insert(QStringLiteral("fastGroupTagBytes"), QString::number(u64FastGroupTagBytes));
            objRecord.insert(QStringLiteral("totalBytes"), QString::number(sumCost.u64TotalBytes()));

            appendCommon(
                QStringLiteral("COMMUNICATION_COST"),
                sumCost.u64TimestampMilliseconds(),
                sumCost.strRoundId(),
                sumCost.strSenderId(),
                sumCost.u64ChainId(),
                strMetricMode(sumCost.modeAuthentication())
            );
            lstColumns << QString() << QString() << QString()
                       << QString() << QString() << QString()
                       << QString() << QString() << QString()
                       << QString::number(u64MessageBytes)
                       << QString::number(u64KeyBytes)
                       << QString::number(u64MacBytes)
                       << QString::number(u64TauBytes)
                       << QString::number(u64FastGroupTagBytes)
                       << strCsv(QStringLiteral("total=%1").arg(sumCost.u64TotalBytes()));
        }
        else
        {
            // 逐轮归档由报文与异常页的专用按钮导出，指标文件只保留采样和估算记录。
            continue;
        }

        arrRecords.append(objRecord);
        strContent += lstColumns.join(QLatin1Char(',')) + QStringLiteral("\r\n");
    }

    QFile fOutput(strFilePath);
    if (!fOutput.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::critical(
            m_pComputationPage,
            QStringLiteral("导出失败"),
            QStringLiteral("无法写入所选文件。")
        );
        return;
    }

    const QByteArray arrBytes = bJson
        ? QJsonDocument(arrRecords).toJson(QJsonDocument::Indented)
        : strContent.toUtf8();
    if (fOutput.write(arrBytes) != arrBytes.size())
    {
        QMessageBox::critical(
            m_pComputationPage,
            QStringLiteral("导出失败"),
            QStringLiteral("文件未能完整写入。")
        );
        return;
    }

    QMessageBox::information(
        m_pComputationPage,
        QStringLiteral("导出完成"),
        QStringLiteral("已导出 %1 条认证指标记录。")
            .arg(static_cast<qulonglong>(arrRecords.size()))
    );
}

void AuthenticationMetricsView::configureSeries(
    QLineSeries* pSeries,
    const QString& strName
)
{
    pSeries->setName(strName);
    pSeries->setPointsVisible(true);
    pSeries->setMarkerSize(5.0);
}

void AuthenticationMetricsView::updateAxes(
    QValueAxis* pXAxis,
    QValueAxis* pYAxis,
    qreal dMaximumX,
    qreal dMaximumY
)
{
    pXAxis->setRange(0.0, std::max<qreal>(1.0, dMaximumX + 1.0));
    pYAxis->setRange(0.0, std::max<qreal>(1.0, dMaximumY * 1.10));
}
