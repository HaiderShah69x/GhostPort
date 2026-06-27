#include "StateLedger.hpp"

bool StateLedger::RegisterKnock(const std::string& ip_address, int port_knocked) {
    std::lock_guard<std::mutex> lock(ledger_mutex);
    auto now = std::chrono::steady_clock::now();

    if (port_knocked == 7000) {
        ledger_matrix[ip_address] = { KnockStage::Port7000_Passed, now };
        return true;
    }

    auto it = ledger_matrix.find(ip_address);
    if (it != ledger_matrix.end()) {
        ClientProgressState& state = it->second;
        
        if (port_knocked == 8000) {
            if (state.current_stage == KnockStage::Port7000_Passed) {
                auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - state.last_knock_time).count();
                if (duration < 5) {
                    state.current_stage = KnockStage::Port8000_Passed;
                    state.last_knock_time = now;
                    return true;
                }
            }
        }
        else if (port_knocked == 9000) {
            if (state.current_stage == KnockStage::Port8000_Passed) {
                auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - state.last_knock_time).count();
                if (duration < 5) {
                    state.current_stage = KnockStage::Fully_Authorized;
                    state.last_knock_time = now;
                    return true;
                }
            }
        }
    }

    // Erase the record immediately for all other cases, out-of-order knocks, or timeouts
    ledger_matrix.erase(ip_address);
    return false;
}

void StateLedger::FlushExpiredNodes(int timeout_seconds) {
    std::lock_guard<std::mutex> lock(ledger_mutex);
    auto now = std::chrono::steady_clock::now();
    
    for (auto it = ledger_matrix.begin(); it != ledger_matrix.end();) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_knock_time).count();
        if (elapsed > timeout_seconds) {
            it = ledger_matrix.erase(it);
        } else {
            ++it;
        }
    }
}

KnockStage StateLedger::GetStage(const std::string& ip_address) {
    std::lock_guard<std::mutex> lock(ledger_mutex);
    auto it = ledger_matrix.find(ip_address);
    if (it != ledger_matrix.end()) {
        return it->second.current_stage;
    }
    return KnockStage::None;
}

void StateLedger::RemoveNode(const std::string& ip_address) {
    std::lock_guard<std::mutex> lock(ledger_mutex);
    ledger_matrix.erase(ip_address);
}
