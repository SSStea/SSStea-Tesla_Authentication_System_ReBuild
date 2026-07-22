#pragma once

#include "AttackTestNetworkController.h"

#include <QMainWindow>
#include <QHash>

#include <cstdint>

class QLabel;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;

/** @brief 攻击测试端主窗口。 */
class AttackTestMainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit AttackTestMainWindow(
        std::uint16_t u16DiscoveryPort = 37020,
        std::uint16_t u16MulticastPort = 39020,
        QWidget* pParent = nullptr
    );

private:
    QWidget* pCreateDatagramPage();
    QWidget* pCreateHighRatePage();
    QWidget* pCreateLogPage();
    void resetRoundRecords();
    void refreshRecords();
    void refreshMode();
    void broadcastSelected();
    void startHighRateTraffic();
    void refreshHighRateControls();
    void appendLog(const QString& strMessage);
    void applyStyle();

    AttackTestNetworkController m_ctlNetwork;
    QPushButton*   m_pMessageConflictButton;
    QPushButton*   m_pDelayedDuplicateButton;
    QTableWidget*  m_pDatagramTable;
    QPushButton*   m_pBroadcastButton;
    QSpinBox*      m_pRateSpin;
    QSpinBox*      m_pDurationSpin;
    QSpinBox*      m_pDatagramBytesSpin;
    QPushButton*   m_pHighRateStartButton;
    QPushButton*   m_pHighRateStopButton;
    QLabel*        m_pHighRateStateLabel;
    QPlainTextEdit* m_pLogEdit;
    QHash<qulonglong, QString> m_mapEditedMessages;
    bool m_bRefreshingRecords;
    bool m_bRecordRefreshPending;
};
