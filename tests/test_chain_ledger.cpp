#include <gtest/gtest.h>
#include "persistence/chain_ledger.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <atomic>
#include <chrono>
#include <cstdint>

namespace {
std::atomic<uint64_t> next_test_directory{0};

struct LedgerFiles {
    std::filesystem::path directory;
    std::filesystem::path binary = directory / "ledger.chain";
    std::filesystem::path json = directory / "ledger.json";

    LedgerFiles() {
        const auto timestamp = std::chrono::steady_clock::now()
                                   .time_since_epoch().count();
        directory = std::filesystem::temp_directory_path() /
            ("aegisxii-ledger-recovery-test-" + std::to_string(timestamp) +
             "-" + std::to_string(next_test_directory.fetch_add(1)));
        binary = directory / "ledger.chain";
        json = directory / "ledger.json";
        std::filesystem::create_directories(directory);
    }
    ~LedgerFiles() { std::filesystem::remove_all(directory); }
};
}

TEST(ChainLedgerTest, RestoresIndexAndHashAcrossRestart) {
    LedgerFiles files;
    SHA256::Digest recovered_tip{};

    {
        fw::ChainLedger ledger(files.binary.string(), files.json.string());
        ASSERT_TRUE(ledger.open());
        ASSERT_EQ(ledger.block_count(), 1u); // genesis
        ledger.commit(fw::LedgerEventType::FIREWALL_START, "first run");
        ledger.close(); // drains the asynchronous queue
        ASSERT_EQ(ledger.block_count(), 2u);
        recovered_tip = ledger.chain_tip();
    }

    {
        fw::ChainLedger ledger(files.binary.string(), files.json.string());
        ASSERT_TRUE(ledger.open());
        EXPECT_EQ(ledger.block_count(), 2u);
        EXPECT_EQ(ledger.chain_tip(), recovered_tip);
        ledger.commit(fw::LedgerEventType::POLICY_CHANGE, "second run");
        ledger.close();
        EXPECT_EQ(ledger.block_count(), 3u);
        const auto verified = ledger.verify_chain();
        EXPECT_TRUE(verified.first) << verified.second;
    }
}

TEST(ChainLedgerTest, RefusesPartialTailInsteadOfAppendingToIt) {
    LedgerFiles files;
    {
        fw::ChainLedger ledger(files.binary.string(), files.json.string());
        ASSERT_TRUE(ledger.open());
        ledger.close();
    }

    {
        std::ofstream out(files.binary, std::ios::binary | std::ios::app);
        ASSERT_TRUE(out.is_open());
        out.put('\x7f'); // incomplete next block
    }

    fw::ChainLedger ledger(files.binary.string(), files.json.string());
    EXPECT_FALSE(ledger.open());
    const auto verified = ledger.verify_chain();
    EXPECT_FALSE(verified.first);
    EXPECT_NE(verified.second.find("corrupt block"), std::string::npos);
}

TEST(ChainLedgerTest, DetectsModifiedBlockOnOpen) {
    LedgerFiles files;
    {
        fw::ChainLedger ledger(files.binary.string(), files.json.string());
        ASSERT_TRUE(ledger.open());
        ledger.close();
    }

    {
        std::fstream file(files.binary,
                          std::ios::binary | std::ios::in | std::ios::out);
        ASSERT_TRUE(file.is_open());
        file.seekp(19); // first byte of genesis event payload
        file.put('X');
    }

    fw::ChainLedger ledger(files.binary.string(), files.json.string());
    EXPECT_FALSE(ledger.open());
    const auto verified = ledger.verify_chain();
    EXPECT_FALSE(verified.first);
    EXPECT_NE(verified.second.find("hash mismatch"), std::string::npos);
}
