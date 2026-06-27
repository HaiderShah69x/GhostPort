#pragma once

#include <string>
#include <map>
#include <mutex>
#include <chrono>

enum class KnockStage { 
    None, 
    Port7000_Passed, 
    Port8000_Passed, 
    Fully_Authorized 
};

struct ClientProgressState {
    KnockStage current_stage;
    std::chrono::steady_clock::time_point last_knock_time;
};

class StateLedger {
private:
    std::map<std::string, ClientProgressState> ledger_matrix;
    std::mutex ledger_mutex;

public:
    StateLedger() = default;
    ~StateLedger() = default;

    bool RegisterKnock(const std::string& ip_address, int port_knocked);
    void FlushExpiredNodes(int timeout_seconds);
    KnockStage GetStage(const std::string& ip_address);
    void RemoveNode(const std::string& ip_address);
};
