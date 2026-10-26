
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

enum class BehaviorEventType
{
    ProcessStarted,
    AutorunChanged,
    FileChangeObserved
};

struct BehaviorEvent
{
    BehaviorEventType type =
        BehaviorEventType::ProcessStarted;

    std::uint32_t processId = 0;
    std::string processName;
    std::string details;
};

struct BehaviorAlert
{
    int score = 0;
    std::uint32_t processId = 0;
    std::string processName;
    std::vector<std::string> findings;
};

class BehaviorMonitor
{
public:
    
    void recordEvent(const BehaviorEvent& event);

    
    [[nodiscard]]
    std::vector<BehaviorAlert> takeAlerts();

    void clear();

private:
    mutable std::mutex mutex_;
    std::vector<BehaviorAlert> alerts_;
    unsigned consecutiveFileChanges_ = 0;
};
