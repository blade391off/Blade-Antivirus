
#include "behavior_monitor.h"

#include <utility>

void BehaviorMonitor::recordEvent(
    const BehaviorEvent& event)
{
    std::lock_guard<std::mutex> lock(mutex_);

    BehaviorAlert alert;
    alert.processId = event.processId;
    alert.processName = event.processName;

    switch (event.type)
    {
    case BehaviorEventType::ProcessStarted:
        return;

    case BehaviorEventType::AutorunChanged:
        alert.score = 20;
        alert.findings.emplace_back(
            "Autostart configuration changed; verify the change");

        if (!event.details.empty())
            alert.findings.push_back(event.details);

        break;

    case BehaviorEventType::FileChangeObserved:
        ++consecutiveFileChanges_;

        if (consecutiveFileChanges_ < 50)
            return;

        alert.score = 20;
        alert.findings.emplace_back(
            "High volume of reported file changes; investigate further");

        consecutiveFileChanges_ = 0;
        break;
    }

    alerts_.push_back(std::move(alert));
}

std::vector<BehaviorAlert> BehaviorMonitor::takeAlerts()
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<BehaviorAlert> result;
    result.swap(alerts_);

    return result;
}

void BehaviorMonitor::clear()
{
    std::lock_guard<std::mutex> lock(mutex_);

    alerts_.clear();
    consecutiveFileChanges_ = 0;
}
