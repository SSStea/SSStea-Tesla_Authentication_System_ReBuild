#include "algorithm/ImprovedTeslaStrategy.h"

#include "algorithm/ImprovedTeslaDetails.h"
#include "algorithm/KsRsMatrix.h"
#include "algorithm/SamdAggregator.h"
#include "algorithm/TeslaMac.h"
#include "crypto/CryptoUtilities.h"

#include <numeric>
#include <optional>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace tesla::core
{
ImprovedTeslaStrategy::ImprovedTeslaStrategy(
    const crypto::CryptoProvider& crpProvider,
    std::size_t nGroupSize,
    std::size_t nDetectionThreshold
)
    : m_crpProvider(crpProvider), m_matKsRs(nGroupSize, nDetectionThreshold)
{
}

TeslaAuthenticationDetails
ImprovedTeslaStrategy::authCreateAuthenticationDetails(
    const AuthenticationGroupInput& grpInput,
    const crypto::Digest& digDataKey
) const
{
    return authCreateAuthenticationDetailsForKeys(
        grpInput,
        std::vector<crypto::Digest>(grpInput.nPacketSlotCount(), digDataKey),
        digDataKey
    );
}

TeslaAuthenticationDetails
ImprovedTeslaStrategy::authCreateAuthenticationDetailsForKeys(
    const AuthenticationGroupInput& grpInput,
    const std::vector<crypto::Digest>& vecPacketDataKeys,
    const crypto::Digest& digFastGroupDataKey
) const
{
    if (grpInput.bHasMissingPackets())
    {
        throw std::invalid_argument(
            "Improved Sender input must not contain missing packets"
        );
    }

    if (grpInput.nPacketSlotCount() > m_matKsRs.nGroupSize())
    {
        throw std::invalid_argument(
            "Improved group exceeds configured KS+RS group size"
        );
    }

    if (vecPacketDataKeys.size() != grpInput.nPacketSlotCount())
    {
        throw std::invalid_argument(
            "Improved packet data keys must match the group slots"
        );
    }

    // 发送端先计算逐包MAC，再按矩阵行聚合tau，最后用快速标签绑定整个组。
    std::vector<PacketDataKeySlot> vecPacketDataKeySlots;
    vecPacketDataKeySlots.reserve(vecPacketDataKeys.size());
    for (const crypto::Digest& digPacketDataKey : vecPacketDataKeys)
    {
        vecPacketDataKeySlots.emplace_back(digPacketDataKey);
    }
    const std::vector<std::optional<crypto::Digest>> vecPacketMacSlots
        = vecComputePacketMacSlots(grpInput, vecPacketDataKeySlots);
    std::vector<crypto::Digest> vecPacketMacs;
    vecPacketMacs.reserve(vecPacketMacSlots.size());

    for (const std::optional<crypto::Digest>& optPacketMac : vecPacketMacSlots)
    {
        vecPacketMacs.push_back(optPacketMac.value());
    }

    std::vector<crypto::Digest> vecSamdTau
        = SamdAggregator::vecAggregate(m_crpProvider, m_matKsRs, vecPacketMacs);
    const crypto::Digest digFastGroupTag = TeslaMac::digComputeFastGroupTag(
        m_crpProvider,
        digFastGroupDataKey,
        grpInput,
        vecSamdTau
    );

    return ImprovedAuthenticationDetails(
        std::move(vecSamdTau),
        digFastGroupTag
    );
}

TeslaVerificationResult ImprovedTeslaStrategy::vfyVerify(
    const AuthenticationGroupInput& grpInput,
    const TeslaAuthenticationDetails& varReceivedDetails,
    const crypto::Digest& digDataKey,
    metrics::VerificationPerformanceSampler* pPerformanceSampler,
    VerificationMeasurementHandler fnMeasurementHandler
) const
{
    return vfyVerifyForKeys(
        grpInput,
        varReceivedDetails,
        std::vector<PacketDataKeySlot>(grpInput.nPacketSlotCount(), digDataKey),
        digDataKey,
        pPerformanceSampler,
        std::move(fnMeasurementHandler)
    );
}

TeslaVerificationResult ImprovedTeslaStrategy::vfyVerifyForKeys(
    const AuthenticationGroupInput& grpInput,
    const TeslaAuthenticationDetails& varReceivedDetails,
    const std::vector<PacketDataKeySlot>& vecPacketDataKeys,
    const crypto::Digest& digFastGroupDataKey,
    metrics::VerificationPerformanceSampler* pPerformanceSampler,
    VerificationMeasurementHandler fnMeasurementHandler
) const
{
    // variant类型必须与当前策略匹配，防止跨模式错误解释认证字段。
    const ImprovedAuthenticationDetails* pImprovedDetails
        = std::get_if<ImprovedAuthenticationDetails>(&varReceivedDetails);

    if (pImprovedDetails == nullptr)
    {
        throw std::invalid_argument(
            "Improved strategy received native authentication details"
        );
    }

    if (grpInput.nPacketSlotCount() > m_matKsRs.nGroupSize())
    {
        throw std::invalid_argument(
            "Improved group exceeds configured KS+RS group size"
        );
    }

    if (vecPacketDataKeys.size() != grpInput.nPacketSlotCount())
    {
        throw std::invalid_argument(
            "Improved packet data key slots must match the group slots"
        );
    }

    const bool bMeasure = pPerformanceSampler != nullptr
                          && static_cast<bool>(fnMeasurementHandler);
    if (bMeasure)
    {
        pPerformanceSampler->begin();
    }
    const auto fnFinishMeasurement = [&]()
    {
        if (bMeasure)
        {
            fnMeasurementHandler(0, pPerformanceSampler->mstEnd());
        }
    };

    // tau数量不完整或快速标签缺失时，既不能走快速路径也不能安全回退。
    if (pImprovedDetails->vecSamdTau().size() != m_matKsRs.nRowCount()
        || !pImprovedDetails->optFastGroupTag().has_value())
    {
        TeslaVerificationResult vfyResult(
            false,
            ImprovedVerificationDetails(
                ImprovedVerificationPath::IncompleteGroupTags,
                false,
                {},
                {},
                false
            )
        );
        fnFinishMeasurement();
        return vfyResult;
    }

    // 完整组优先验证一次快速标签；成功时不再执行任何逐包MAC计算。
    if (!grpInput.bHasMissingPackets())
    {
        const crypto::Digest digCalculatedFastGroupTag
            = TeslaMac::digComputeFastGroupTag(
                m_crpProvider,
                digFastGroupDataKey,
                grpInput,
                pImprovedDetails->vecSamdTau()
            );

        if (crypto::CryptoUtilities::bDigestEquals(
                digCalculatedFastGroupTag,
                pImprovedDetails->optFastGroupTag().value()
            ))
        {
            std::vector<std::size_t> vecAuthenticatedPositions(
                grpInput.nPacketSlotCount()
            );
            std::iota(
                vecAuthenticatedPositions.begin(),
                vecAuthenticatedPositions.end(),
                0
            );

            TeslaVerificationResult vfyResult(
                true,
                ImprovedVerificationDetails(
                    ImprovedVerificationPath::FastGroupPass,
                    true,
                    std::move(vecAuthenticatedPositions),
                    {},
                    false
                )
            );
            fnFinishMeasurement();
            return vfyResult;
        }
    }

    for (std::size_t nPosition = 0; nPosition < grpInput.nPacketSlotCount();
         ++nPosition)
    {
        if (grpInput.vecPacketSlots()[nPosition].has_value()
            && !vecPacketDataKeys[nPosition].has_value())
        {
            return TeslaVerificationResult(
                false,
                ImprovedVerificationDetails(
                    ImprovedVerificationPath::PendingDataKeys,
                    false,
                    {},
                    {},
                    false
                )
            );
        }
    }

    // 快速标签不匹配或存在丢包时，保留原槽位并进入KS+RS定位路径。
    const std::vector<std::optional<crypto::Digest>> vecPacketMacSlots
        = vecComputePacketMacSlots(grpInput, vecPacketDataKeys);
    KsRsVerificationResult resKsRs = KsRsVerifier::resVerify(
        m_crpProvider,
        m_matKsRs,
        vecPacketMacSlots,
        pImprovedDetails->vecSamdTau()
    );

    TeslaVerificationResult vfyResult(
        false,
        ImprovedVerificationDetails(
            ImprovedVerificationPath::KsRsFallback,
            false,
            resKsRs.vecGoodPositions(),
            resKsRs.vecBadPositions(),
            resKsRs.bDetectionThresholdExceeded(),
            resKsRs.vecLocationSteps()
        )
    );
    fnFinishMeasurement();
    return vfyResult;
}

std::vector<std::optional<crypto::Digest>>
ImprovedTeslaStrategy::vecComputePacketMacSlots(
    const AuthenticationGroupInput& grpInput,
    const std::vector<PacketDataKeySlot>& vecPacketDataKeys
) const
{
    std::vector<std::optional<crypto::Digest>> vecPacketMacSlots;
    vecPacketMacSlots.reserve(grpInput.nPacketSlotCount());

    // 空槽位原样传播给KS+RS验证器，实际报文才会重算逐包MAC。
    for (std::size_t nPosition = 0; nPosition < grpInput.nPacketSlotCount();
         ++nPosition)
    {
        const AuthenticationGroupInput::PacketSlot& optPacket
            = grpInput.vecPacketSlots()[nPosition];
        if (!optPacket.has_value())
        {
            vecPacketMacSlots.push_back(std::nullopt);
            continue;
        }

        if (!vecPacketDataKeys[nPosition].has_value())
        {
            throw std::invalid_argument(
                "Improved received packet is missing its disclosed data key"
            );
        }

        vecPacketMacSlots.push_back(TeslaMac::digComputePacketMac(
            m_crpProvider,
            vecPacketDataKeys[nPosition].value(),
            optPacket.value()
        ));
    }

    return vecPacketMacSlots;
}
} // namespace tesla::core
