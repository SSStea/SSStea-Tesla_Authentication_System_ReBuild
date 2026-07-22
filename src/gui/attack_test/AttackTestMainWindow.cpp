#include "AttackTestMainWindow.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QButtonGroup>
#include <QDateTime>
#include <QFormLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>

namespace
{
QTableWidgetItem* pReadOnlyItem(const QString& strText)
{
    QTableWidgetItem* pItem = new QTableWidgetItem(strText);
    pItem->setFlags(pItem->flags() & ~Qt::ItemIsEditable);
    return pItem;
}
}

AttackTestMainWindow::AttackTestMainWindow(
    std::uint16_t u16DiscoveryPort,
    std::uint16_t u16MulticastPort,
    QWidget* pParent
)
    : QMainWindow(pParent),
      m_ctlNetwork(
          u16DiscoveryPort,
          QStringLiteral("239.10.10.10"),
          u16MulticastPort,
          nullptr
      ),
      m_pMessageConflictButton(nullptr),
      m_pDelayedDuplicateButton(nullptr),
      m_pDatagramTable(nullptr),
      m_pBroadcastButton(nullptr),
      m_pRateSpin(nullptr),
      m_pDurationSpin(nullptr),
      m_pDatagramBytesSpin(nullptr),
      m_pHighRateStartButton(nullptr),
      m_pHighRateStopButton(nullptr),
      m_pHighRateStateLabel(nullptr),
      m_pLogEdit(nullptr),
      m_bRefreshingRecords(false),
      m_bRecordRefreshPending(false)
{
    setWindowTitle(QStringLiteral("TESLA 攻击测试端"));
    resize(1180, 760);

    QWidget* pCentralWidget = new QWidget(this);
    QVBoxLayout* pRootLayout = new QVBoxLayout(pCentralWidget);
    QLabel* pTitleLabel = new QLabel(
        QStringLiteral("无人机传输认证系统 · 攻击测试"),
        pCentralWidget
    );
    pTitleLabel->setObjectName(QStringLiteral("titleLabel"));
    pRootLayout->addWidget(pTitleLabel);

    QTabWidget* pTabs = new QTabWidget(pCentralWidget);
    pTabs->addTab(pCreateDatagramPage(), QStringLiteral("报文监听"));
    pTabs->addTab(pCreateHighRatePage(), QStringLiteral("Dos"));
    pTabs->addTab(pCreateLogPage(), QStringLiteral("日志"));
    pRootLayout->addWidget(pTabs, 1);
    setCentralWidget(pCentralWidget);

    connect(
        &m_ctlNetwork,
        &AttackTestNetworkController::recordsChanged,
        this,
        &AttackTestMainWindow::refreshRecords
    );
    connect(
        &m_ctlNetwork,
        &AttackTestNetworkController::roundChanged,
        this,
        &AttackTestMainWindow::resetRoundRecords
    );
    connect(
        &m_ctlNetwork,
        &AttackTestNetworkController::stateChanged,
        this,
        &AttackTestMainWindow::refreshHighRateControls
    );
    connect(
        &m_ctlNetwork,
        &AttackTestNetworkController::logMessage,
        this,
        &AttackTestMainWindow::appendLog
    );

    applyStyle();
    if (!m_ctlNetwork.bStart())
    {
        appendLog(QStringLiteral("攻击测试端启动失败"));
    }
    else
    {
        statusBar()->showMessage(
            QStringLiteral("后台发现已启动，本地地址：%1")
                .arg(m_ctlNetwork.strLocalIpv4Address())
        );
    }
    refreshHighRateControls();
}

QWidget* AttackTestMainWindow::pCreateDatagramPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);

    QHBoxLayout* pModeLayout = new QHBoxLayout();
    QLabel* pModeLabel = new QLabel(QStringLiteral("广播方式"), pPage);
    m_pMessageConflictButton = new QPushButton(
        QStringLiteral("篡改"),
        pPage
    );
    m_pDelayedDuplicateButton = new QPushButton(
        QStringLiteral("重放"),
        pPage
    );
    m_pMessageConflictButton->setCheckable(true);
    m_pDelayedDuplicateButton->setCheckable(true);
    m_pMessageConflictButton->setChecked(true);
    m_pMessageConflictButton->setObjectName(QStringLiteral("modeButton"));
    m_pDelayedDuplicateButton->setObjectName(QStringLiteral("modeButton"));
    QButtonGroup* pModeGroup = new QButtonGroup(pPage);
    pModeGroup->setExclusive(true);
    pModeGroup->addButton(m_pMessageConflictButton);
    pModeGroup->addButton(m_pDelayedDuplicateButton);
    pModeLayout->addWidget(pModeLabel);
    pModeLayout->addWidget(m_pMessageConflictButton);
    pModeLayout->addWidget(m_pDelayedDuplicateButton);
    pModeLayout->addStretch(1);
    pLayout->addLayout(pModeLayout);

    QLabel* pHintLabel = new QLabel(
        QStringLiteral(
            "篡改允许直接修改所选Message中的一位或多位；"
            "重放会原样广播所选数据报。"
        ),
        pPage
    );
    pHintLabel->setObjectName(QStringLiteral("hintLabel"));
    pLayout->addWidget(pHintLabel);

    m_pDatagramTable = new QTableWidget(0, 3, pPage);
    m_pDatagramTable->setHorizontalHeaderLabels({
        QStringLiteral("时间"),
        QStringLiteral("Sender"),
        QStringLiteral("Message")
    });
    m_pDatagramTable->horizontalHeader()->setSectionResizeMode(
        QHeaderView::Stretch
    );
    m_pDatagramTable->verticalHeader()->setVisible(false);
    m_pDatagramTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_pDatagramTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_pDatagramTable->setAlternatingRowColors(true);
    pLayout->addWidget(m_pDatagramTable, 1);

    m_pBroadcastButton = new QPushButton(QStringLiteral("广播"), pPage);
    m_pBroadcastButton->setObjectName(QStringLiteral("primaryButton"));
    pLayout->addWidget(m_pBroadcastButton);

    connect(
        m_pMessageConflictButton,
        &QPushButton::toggled,
        this,
        &AttackTestMainWindow::refreshMode
    );
    connect(
        m_pBroadcastButton,
        &QPushButton::clicked,
        this,
        &AttackTestMainWindow::broadcastSelected
    );
    connect(
        m_pDatagramTable,
        &QTableWidget::itemChanged,
        this,
        [this](QTableWidgetItem* pItem)
        {
            if (m_bRefreshingRecords || pItem == nullptr
                || pItem->column() != 2)
            {
                return;
            }

            QTableWidgetItem* pTimeItem = m_pDatagramTable->item(
                pItem->row(),
                0
            );
            if (pTimeItem != nullptr)
            {
                m_mapEditedMessages.insert(
                    pTimeItem->data(Qt::UserRole).toULongLong(),
                    pItem->text().trimmed().toUpper()
                );
            }

            if (m_bRecordRefreshPending)
            {
                QTimer::singleShot(
                    0,
                    this,
                    &AttackTestMainWindow::refreshRecords
                );
            }
        }
    );
    return pPage;
}

QWidget* AttackTestMainWindow::pCreateHighRatePage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    QFormLayout* pForm = new QFormLayout();

    m_pRateSpin = new QSpinBox(pPage);
    m_pRateSpin->setRange(1, 500000);
    m_pRateSpin->setValue(10000);
    m_pRateSpin->setButtonSymbols(QAbstractSpinBox::NoButtons);
    pForm->addRow(QStringLiteral("每秒报文数"), m_pRateSpin);

    m_pDurationSpin = new QSpinBox(pPage);
    m_pDurationSpin->setRange(1, 3600000);
    m_pDurationSpin->setValue(10000);
    m_pDurationSpin->setSuffix(QStringLiteral(" ms"));
    m_pDurationSpin->setButtonSymbols(QAbstractSpinBox::NoButtons);
    pForm->addRow(QStringLiteral("持续时间"), m_pDurationSpin);

    m_pDatagramBytesSpin = new QSpinBox(pPage);
    m_pDatagramBytesSpin->setRange(1, 1400);
    m_pDatagramBytesSpin->setValue(64);
    m_pDatagramBytesSpin->setSuffix(QStringLiteral(" B"));
    m_pDatagramBytesSpin->setButtonSymbols(QAbstractSpinBox::NoButtons);
    pForm->addRow(QStringLiteral("单条长度"), m_pDatagramBytesSpin);
    pLayout->addLayout(pForm);

    m_pHighRateStateLabel = new QLabel(QStringLiteral("状态：未运行"), pPage);
    pLayout->addWidget(m_pHighRateStateLabel);

    QHBoxLayout* pButtonLayout = new QHBoxLayout();
    m_pHighRateStartButton = new QPushButton(QStringLiteral("开始广播"), pPage);
    m_pHighRateStopButton = new QPushButton(QStringLiteral("停止"), pPage);
    m_pHighRateStartButton->setObjectName(QStringLiteral("primaryButton"));
    pButtonLayout->addWidget(m_pHighRateStartButton);
    pButtonLayout->addWidget(m_pHighRateStopButton);
    pButtonLayout->addStretch(1);
    pLayout->addLayout(pButtonLayout);
    pLayout->addStretch(1);

    connect(
        m_pHighRateStartButton,
        &QPushButton::clicked,
        this,
        &AttackTestMainWindow::startHighRateTraffic
    );
    connect(
        m_pHighRateStopButton,
        &QPushButton::clicked,
        &m_ctlNetwork,
        &AttackTestNetworkController::stopHighRateTraffic
    );
    return pPage;
}

QWidget* AttackTestMainWindow::pCreateLogPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    m_pLogEdit = new QPlainTextEdit(pPage);
    m_pLogEdit->setReadOnly(true);
    m_pLogEdit->setMaximumBlockCount(3000);
    pLayout->addWidget(m_pLogEdit);
    return pPage;
}

void AttackTestMainWindow::resetRoundRecords()
{
    m_mapEditedMessages.clear();
    m_bRecordRefreshPending = false;
    m_bRefreshingRecords = true;
    m_pDatagramTable->clearContents();
    m_pDatagramTable->setRowCount(0);
    m_bRefreshingRecords = false;
}

void AttackTestMainWindow::refreshRecords()
{
    QWidget* pFocusedWidget = QApplication::focusWidget();
    if (qobject_cast<QLineEdit*>(pFocusedWidget) != nullptr
        && m_pDatagramTable->isAncestorOf(pFocusedWidget))
    {
        m_bRecordRefreshPending = true;
        return;
    }

    m_bRecordRefreshPending = false;
    QTableWidgetItem* pSelectedIdItem = m_pDatagramTable->currentRow() >= 0
        ? m_pDatagramTable->item(m_pDatagramTable->currentRow(), 0)
        : nullptr;
    const qulonglong u64SelectedRecordId = pSelectedIdItem == nullptr
        ? 0
        : pSelectedIdItem->data(Qt::UserRole).toULongLong();
    const QVector<AttackDatagramRecord> vecRecords =
        m_ctlNetwork.vecRecordSnapshot();

    m_bRefreshingRecords = true;
    m_pDatagramTable->setRowCount(vecRecords.size());
    int nSelectedRow = -1;
    for (qsizetype nIndex = 0; nIndex < vecRecords.size(); ++nIndex)
    {
        const AttackDatagramRecord& recDatagram =
            vecRecords[vecRecords.size() - 1 - nIndex];
        const int nRow = static_cast<int>(nIndex);
        QTableWidgetItem* pTimeItem = pReadOnlyItem(
            QDateTime::fromMSecsSinceEpoch(
                static_cast<qint64>(
                    recDatagram.u64CaptureTimestampMilliseconds()
                )
            ).toString(QStringLiteral("HH:mm:ss.zzz"))
        );
        pTimeItem->setData(
            Qt::UserRole,
            QVariant::fromValue<qulonglong>(recDatagram.u64RecordId())
        );
        m_pDatagramTable->setItem(nRow, 0, pTimeItem);
        m_pDatagramTable->setItem(
            nRow,
            1,
            pReadOnlyItem(recDatagram.strSenderAddress())
        );

        const qulonglong u64RecordId = recDatagram.u64RecordId();
        const QString strMessage = m_mapEditedMessages.contains(u64RecordId)
            ? m_mapEditedMessages.value(u64RecordId)
            : recDatagram.strMessageHex();
        QTableWidgetItem* pMessageItem = new QTableWidgetItem(strMessage);
        if (!m_pMessageConflictButton->isChecked())
        {
            pMessageItem->setFlags(
                pMessageItem->flags() & ~Qt::ItemIsEditable
            );
        }
        m_pDatagramTable->setItem(nRow, 2, pMessageItem);
        if (u64RecordId == u64SelectedRecordId)
        {
            nSelectedRow = nRow;
        }
    }
    if (nSelectedRow >= 0)
    {
        m_pDatagramTable->selectRow(nSelectedRow);
    }
    m_bRefreshingRecords = false;
}

void AttackTestMainWindow::refreshMode()
{
    refreshRecords();
}

void AttackTestMainWindow::broadcastSelected()
{
    const int nRow = m_pDatagramTable->currentRow();
    if (nRow < 0)
    {
        QMessageBox::information(this, QStringLiteral("提示"),
            QStringLiteral("请先选择一条报文"));
        return;
    }

    const std::uint64_t u64RecordId = m_pDatagramTable->item(
        nRow,
        0
    )->data(Qt::UserRole).toULongLong();
    QString strError;
    bool bSent = false;
    if (m_pMessageConflictButton->isChecked())
    {
        const QString strMessage = m_pDatagramTable->item(nRow, 2)
            ->text().trimmed().toUpper();
        bSent = m_ctlNetwork.bBroadcastMessageConflict(
            u64RecordId,
            strMessage,
            strError
        );
    }
    else
    {
        bSent = m_ctlNetwork.bBroadcastDelayedDuplicate(
            u64RecordId,
            strError
        );
    }

    if (!bSent)
    {
        QMessageBox::warning(this, QStringLiteral("广播失败"), strError);
    }
}

void AttackTestMainWindow::startHighRateTraffic()
{
    QString strError;
    if (!m_ctlNetwork.bStartHighRateTraffic(
            static_cast<std::uint32_t>(m_pRateSpin->value()),
            static_cast<std::uint32_t>(m_pDurationSpin->value()),
            static_cast<std::uint32_t>(m_pDatagramBytesSpin->value()),
            strError
        ))
    {
        QMessageBox::warning(this, QStringLiteral("无法开始"), strError);
    }
}

void AttackTestMainWindow::refreshHighRateControls()
{
    const bool bRunning = m_ctlNetwork.bHighRateTrafficRunning();
    m_pRateSpin->setEnabled(!bRunning);
    m_pDurationSpin->setEnabled(!bRunning);
    m_pDatagramBytesSpin->setEnabled(!bRunning);
    m_pHighRateStartButton->setEnabled(!bRunning);
    m_pHighRateStopButton->setEnabled(bRunning);
    m_pHighRateStateLabel->setText(
        bRunning ? QStringLiteral("状态：广播中")
                 : QStringLiteral("状态：未运行")
    );
}

void AttackTestMainWindow::appendLog(const QString& strMessage)
{
    m_pLogEdit->appendPlainText(
        QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz "))
        + strMessage
    );
}

void AttackTestMainWindow::applyStyle()
{
    setStyleSheet(QStringLiteral(R"(
        QMainWindow, QWidget { background: #f7f9fc; color: #16324f; }
        QLabel#titleLabel { font-size: 22px; font-weight: 700; padding: 12px 4px; }
        QLabel#hintLabel { color: #5c7290; padding: 4px 0 8px 0; }
        QTabWidget::pane { border: 1px solid #d7e0ec; background: white; }
        QTableWidget, QPlainTextEdit, QSpinBox {
            background: white; border: 1px solid #d7e0ec; border-radius: 4px;
        }
        QPushButton { min-height: 32px; padding: 0 18px; border: 1px solid #c8d4e3; border-radius: 5px; background: white; }
        QPushButton:hover { border-color: #2b67e8; }
        QPushButton#modeButton:checked, QPushButton#primaryButton {
            color: white; border-color: #2b67e8; background: #2b67e8;
        }
        QPushButton:disabled { color: #9aa8ba; background: #edf1f6; }
        QHeaderView::section { background: #eef3f9; border: 0; border-right: 1px solid #d7e0ec; padding: 7px; font-weight: 600; }
    )"));
}
