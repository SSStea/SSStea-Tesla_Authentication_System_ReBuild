#include "PcNodeMainWindow.h"

#include "AuthenticationMonitorWidget.h"
#include "PcAuthenticationViews.h"

#include <QDateTime>
#include <QGridLayout>
#include <QLabel>
#include <QMessageBox>
#include <QTabWidget>
#include <QTextEdit>
#include <QVBoxLayout>

namespace
{
QLabel* pCreateStateValue(QWidget* pParent)
{
    QLabel* pLabel = new QLabel(QStringLiteral("未知"), pParent);
    pLabel->setObjectName(QStringLiteral("stateValue"));
    return pLabel;
}
}

PcNodeMainWindow::PcNodeMainWindow(
    std::uint16_t u16DiscoveryPort,
    std::uint16_t u16ManagementPort,
    QWidget* pParent
)
    : QMainWindow(pParent),
      m_ctlNetwork(
          u16DiscoveryPort,
          u16ManagementPort,
          std::chrono::milliseconds(1000),
          nullptr
      ),
      m_pServiceValue(nullptr),
      m_pTcpValue(nullptr),
      m_pUdpValue(nullptr),
      m_pSenderValue(nullptr),
      m_pReceiverValue(nullptr),
      m_pLogEdit(nullptr),
      m_pAuthenticationMonitor(nullptr),
      m_pKeyChainWidget(nullptr),
      m_pMatrixWidget(nullptr)
{
    setWindowTitle(QStringLiteral("无人机传输认证系统 PC节点"));
    resize(1220, 760);

    QWidget* pCentralWidget = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pCentralWidget);
    QLabel* pTitleLabel = new QLabel(
        QStringLiteral("无人机传输认证系统 PC节点 · ")
            + m_ctlNetwork.strNodeName(),
        pCentralWidget
    );
    pTitleLabel->setObjectName(QStringLiteral("titleLabel"));
    pLayout->addWidget(pTitleLabel);

    QTabWidget* pTabs = new QTabWidget(pCentralWidget);
    pTabs->addTab(pCreateStatusPage(), QStringLiteral("节点状态"));
    m_pAuthenticationMonitor = new tesla::gui::AuthenticationMonitorWidget(
        pTabs
    );
    pTabs->addTab(m_pAuthenticationMonitor, QStringLiteral("报文与展示"));
    m_pKeyChainWidget = new PcLocalKeyChainWidget(pTabs);
    pTabs->addTab(m_pKeyChainWidget, QStringLiteral("密钥链"));
    m_pMatrixWidget = new PcMatrixLocationWidget(pTabs);
    pTabs->addTab(m_pMatrixWidget, QStringLiteral("矩阵"));
    pTabs->addTab(pCreateLogPage(), QStringLiteral("日志"));
    pLayout->addWidget(pTabs, 1);
    setCentralWidget(pCentralWidget);
    applyStyle();

    connect(
        &m_ctlNetwork,
        &PcNodeNetworkController::stateChanged,
        this,
        &PcNodeMainWindow::refreshStatus
    );
    connect(
        &m_ctlNetwork,
        &PcNodeNetworkController::logMessage,
        this,
        &PcNodeMainWindow::appendLog
    );
    connect(
        &m_ctlNetwork,
        &PcNodeNetworkController::senderConfigurationReceived,
        this,
        &PcNodeMainWindow::showSenderConfigurationReceived
    );
    connect(
        &m_ctlNetwork,
        &PcNodeNetworkController::authenticationObservationsChanged,
        this,
        &PcNodeMainWindow::refreshAuthenticationViews
    );
    connect(
        &m_ctlNetwork,
        &PcNodeNetworkController::localKeyChainChanged,
        this,
        &PcNodeMainWindow::refreshAuthenticationViews
    );

    if (!m_ctlNetwork.bStart())
    {
        appendLog(QStringLiteral("PC节点网络服务启动失败"));
    }
    refreshStatus();
    refreshAuthenticationViews();
}

void PcNodeMainWindow::showSenderConfigurationReceived()
{
    QMessageBox* pMessage = new QMessageBox(this);
    pMessage->setAttribute(Qt::WA_DeleteOnClose);
    pMessage->setWindowTitle(QStringLiteral("配置接收成功"));
    pMessage->setIcon(QMessageBox::Information);
    pMessage->setText(QStringLiteral("Sender 已接收到本轮配置"));
    pMessage->setInformativeText(QStringLiteral(
        "请等待管理单元启动认证轮次。"
    ));
    pMessage->addButton(QStringLiteral("确定"), QMessageBox::AcceptRole);
    pMessage->setMinimumSize(360, 170);
    pMessage->open();
}

QWidget* PcNodeMainWindow::pCreateStatusPage()
{
    QWidget* pPage = new QWidget(this);
    QGridLayout* pLayout = new QGridLayout(pPage);
    pLayout->setColumnStretch(1, 1);

    m_pServiceValue = pCreateStateValue(pPage);
    m_pTcpValue = pCreateStateValue(pPage);
    m_pUdpValue = pCreateStateValue(pPage);
    m_pSenderValue = pCreateStateValue(pPage);
    m_pReceiverValue = pCreateStateValue(pPage);

    pLayout->addWidget(new QLabel(QStringLiteral("节点服务"), pPage), 0, 0);
    pLayout->addWidget(m_pServiceValue, 0, 1);
    pLayout->addWidget(new QLabel(QStringLiteral("TCP管理连接"), pPage), 1, 0);
    pLayout->addWidget(m_pTcpValue, 1, 1);
    pLayout->addWidget(new QLabel(QStringLiteral("UDP发现/心跳"), pPage), 2, 0);
    pLayout->addWidget(m_pUdpValue, 2, 1);
    pLayout->addWidget(new QLabel(QStringLiteral("Sender"), pPage), 3, 0);
    pLayout->addWidget(m_pSenderValue, 3, 1);
    pLayout->addWidget(new QLabel(QStringLiteral("Receiver"), pPage), 4, 0);
    pLayout->addWidget(m_pReceiverValue, 4, 1);

    QLabel* pHintLabel = new QLabel(
        QStringLiteral(
            "已接入文本与文件认证配置、原生/改进TESLA UDP收发、"
            "文件后台切片、认证恢复及原子落盘。"
        ),
        pPage
    );
    pHintLabel->setWordWrap(true);
    pHintLabel->setObjectName(QStringLiteral("hintLabel"));
    pLayout->addWidget(pHintLabel, 5, 0, 1, 2);
    pLayout->setRowStretch(6, 1);
    return pPage;
}

QWidget* PcNodeMainWindow::pCreateLogPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    m_pLogEdit = new QTextEdit(pPage);
    m_pLogEdit->setReadOnly(true);
    m_pLogEdit->setPlaceholderText(QStringLiteral("真实网络状态日志将在此显示"));
    pLayout->addWidget(m_pLogEdit);
    return pPage;
}

void PcNodeMainWindow::refreshAuthenticationViews()
{
    m_pAuthenticationMonitor->setSnapshots(
        m_ctlNetwork.vecPacketObservationSnapshot(),
        m_ctlNetwork.vecFailureObservationSnapshot(),
        m_ctlNetwork.vecDosSummarySnapshot()
    );
    m_pAuthenticationMonitor->setMetricSnapshots(
        m_ctlNetwork.vecMetricSnapshot()
    );
    m_pKeyChainWidget->setKeyChain(
        m_ctlNetwork.optLocalKeyChainSnapshot(),
        m_ctlNetwork.optLocalKeyChainProgress()
    );
    m_pMatrixWidget->setGroups(
        m_ctlNetwork.vecGroupObservationSnapshot()
    );
}

void PcNodeMainWindow::refreshStatus()
{
    m_pServiceValue->setText(
        m_ctlNetwork.bIsRunning()
            ? QStringLiteral("运行中")
            : QStringLiteral("停止")
    );
    m_pTcpValue->setText(QStringLiteral("%1个客户端")
        .arg(m_ctlNetwork.nConnectedClientCount()));
    m_pUdpValue->setText(
        m_ctlNetwork.bIsRunning()
            ? QStringLiteral("已启用")
            : QStringLiteral("未启用")
    );
    m_pSenderValue->setText(
        m_ctlNetwork.bSenderRunning()
            ? QStringLiteral("运行中")
            : QStringLiteral("空闲")
    );
    m_pReceiverValue->setText(
        m_ctlNetwork.bReceiverRunning()
            ? QStringLiteral("监听中")
            : QStringLiteral("停止")
    );
}

void PcNodeMainWindow::appendLog(const QString& strMessage)
{
    if (m_pLogEdit != nullptr)
    {
        m_pLogEdit->append(
            QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz "))
                + strMessage
        );
    }
}

void PcNodeMainWindow::applyStyle()
{
    setStyleSheet(QStringLiteral(R"(
        QMainWindow, QWidget {
            background: #f6f8fb;
            color: #1f2937;
            font-family: "Microsoft YaHei";
            font-size: 13px;
        }
        QLabel#titleLabel {
            font-size: 22px;
            font-weight: 700;
            color: #17365d;
            padding: 8px 4px;
        }
        QLabel#sectionTitleLabel {
            font-size: 18px;
            font-weight: 600;
            color: #17365d;
        }
        QLabel#stateValue {
            background: white;
            border: 1px solid #dbe3ec;
            border-radius: 5px;
            padding: 10px;
            color: #14532d;
            font-weight: 600;
        }
        QLabel#hintLabel {
            color: #64748b;
            padding: 6px;
        }
        QPushButton {
            background: white;
            border: 1px solid #cbd5e1;
            border-radius: 5px;
            padding: 7px 16px;
        }
        QPushButton:hover {
            color: #1d4ed8;
            background: #dbeafe;
            border-color: #2563eb;
        }
        QPushButton:focus, QPushButton:pressed, QPushButton:checked {
            color: white;
            background: #2563eb;
            border-color: #2563eb;
        }
        QPushButton:disabled {
            color: #94a3b8;
            background: #eef2f7;
        }
        QTabWidget::pane, QTextEdit {
            background: white;
            border: 1px solid #dbe3ec;
        }
        QTabBar::tab {
            color: #475569;
            background: #eef3f9;
            border: 1px solid #d7e0ec;
            border-bottom: 0;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            padding: 6px 14px;
            margin-right: 2px;
        }
        QTabBar::tab:!selected:hover {
            color: #1d4ed8;
            background: #dbeafe;
        }
        QTabBar::tab:selected {
            color: white;
            background: #2563eb;
            border-color: #2563eb;
            font-weight: 600;
        }
    )"));
}
