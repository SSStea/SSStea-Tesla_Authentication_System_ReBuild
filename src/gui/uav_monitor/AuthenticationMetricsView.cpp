#include "AuthenticationMetricsView.h"

#include <QChart>
#include <QChartView>
#include <QLabel>
#include <QLineSeries>
#include <QPainter>
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
constexpr qreal MAX_VISIBLE_ROUND_TICK_COUNT = 10.0;

qreal dNiceRoundTickInterval(qreal dMaximumRound)
{
    const qreal dRawInterval = std::max<qreal>(
        1.0,
        std::ceil(dMaximumRound / MAX_VISIBLE_ROUND_TICK_COUNT)
    );
    const qreal dMagnitude = std::pow(
        10.0,
        std::floor(std::log10(dRawInterval))
    );
    const qreal dNormalizedInterval = dRawInterval / dMagnitude;

    if (dNormalizedInterval <= 1.0)
    {
        return dMagnitude;
    }
    if (dNormalizedInterval <= 2.0)
    {
        return 2.0 * dMagnitude;
    }
    if (dNormalizedInterval <= 5.0)
    {
        return 5.0 * dMagnitude;
    }

    return 10.0 * dMagnitude;
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
        QStringLiteral("能耗"),
        QStringLiteral(
            "每个点表示一轮正常认证的能耗；"
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
    m_pEnergyYAxis->setTitleText(QStringLiteral("能耗 (mJ)"));
    m_pEnergyXAxis->setLabelFormat(QStringLiteral("%.0f"));

    updateAxes(m_pComputationXAxis, m_pComputationYAxis, 1.0, 1.0);
    updateAxes(m_pEnergyXAxis, m_pEnergyYAxis, 1.0, 1.0);

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
        m_pEnergySummary->setText(QStringLiteral("尚无正常轮次能耗"));
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
                "最新正常%1轮次：能耗=%2 mJ；平均每包=%3 μJ；"
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
    pXAxis->setTickType(QValueAxis::TicksDynamic);
    if (dMaximumX < 1.0)
    {
        pXAxis->setTickAnchor(0.0);
        pXAxis->setTickInterval(1.0);
        pXAxis->setRange(0.0, 1.0);
    }
    else
    {
        const qreal dMaximumRound = std::floor(dMaximumX);
        pXAxis->setTickAnchor(1.0);
        pXAxis->setTickInterval(dNiceRoundTickInterval(dMaximumRound));
        pXAxis->setRange(0.5, dMaximumRound + 0.5);
    }

    pYAxis->setRange(0.0, std::max<qreal>(1.0, dMaximumY * 1.10));
}
