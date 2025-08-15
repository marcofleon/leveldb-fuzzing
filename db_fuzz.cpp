#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <random>
#include <unordered_map>
#include <map>
#include <cassert>
#include <optional>
#include <unistd.h>

#include "leveldb/db.h"
#include "leveldb/iterator.h"
#include "leveldb/options.h"
#include "leveldb/status.h"
#include "leveldb/cache.h"
#include "leveldb/filter_policy.h"
#include "leveldb/write_batch.h"

#include "FuzzedDataProvider.h"

#define LIMITED_WHILE(condition, limit, total_size, max_size) \
    for (unsigned _count{limit}; (condition) && _count && total_size < max_size; --_count)

namespace {

class AutoDbDeleter {
    public:
        AutoDbDeleter() {
            
            pid_t pid = getpid();

            std::random_device rd;
            std::mt19937_64 gen(rd());
            std::uniform_int_distribution<uint64_t> dis;
            std::string random_value = std::to_string(dis(gen));
        
            // Format: /tmp/testdb_PID_RANDOM
            db_path_ = std::string("/tmp/testdb_") + std::to_string(pid) + "_" + random_value;
        }

    AutoDbDeleter(const AutoDbDeleter&) = delete;
    AutoDbDeleter& operator=(const AutoDbDeleter&) = delete;

    ~AutoDbDeleter() {
        std::filesystem::remove_all(db_path_);
    }

    const std::string& path() const { return db_path_; }

    private:
        std::string db_path_;
};

static leveldb::Options GetOptions(FuzzedDataProvider& fuzzed_data) 
{
    size_t nCacheSize = fuzzed_data.ConsumeIntegralInRange<size_t>(1024, 1024*1024*32);
    leveldb::Options options;
    options.block_cache = leveldb::NewLRUCache(nCacheSize / 2);
    options.write_buffer_size = nCacheSize / 4; // up to two write buffers may be held in memory simultaneously
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);
    options.compression = leveldb::kNoCompression;
    if (leveldb::kMajorVersion > 1 || (leveldb::kMajorVersion == 1 && leveldb::kMinorVersion >= 16)) {
        options.paranoid_checks = true;
    }
    options.max_file_size = fuzzed_data.ConsumeIntegralInRange<size_t>(1024, 1024*1024*32);
    options.create_if_missing = true;
    return options;
}

std::unique_ptr<leveldb::DB> OpenDB(const std::string& path, FuzzedDataProvider& fuzzed_data) 
{
    leveldb::Options options = GetOptions(fuzzed_data);
  
    leveldb::DB* db_ptr;
    leveldb::Status status = leveldb::DB::Open(options, path, &db_ptr);
    if (!status.ok()) {
        fprintf(stderr, "failure inside open: %s\n", status.ToString().c_str());
        assert(status.ok());
    }

    return std::unique_ptr<leveldb::DB>(db_ptr);
}

enum class FuzzOp {
    kPut = 0,
    kGet = 1,
    kDelete = 2,
    kGetProperty = 3,
    kIterate = 4,
    kGetReleaseSnapshot = 5,
    kReopenDb = 6,
    kCompactRange = 7,
    kWrite = 8,
    kMaxValue = kWrite,
};

bool VerifyContents(leveldb::DB* db, const std::map<std::string, std::string>& reference_map) 
{
    auto print_summary = [](const std::string& str) {
        fprintf(stderr, "(size=%zu) '", str.length());
        for (size_t i = 0; i < std::min(str.length(), (size_t)16); ++i) {
            fprintf(stderr, "%02x", static_cast<unsigned char>(str[i]));
        }
        if (str.length() > 16) {
            fprintf(stderr, "...");
        }
        fprintf(stderr, "'");
    };

    for (const auto& [key, expected_value] : reference_map) {
        std::string actual_value;
        auto status = db->Get(leveldb::ReadOptions(), key, &actual_value);
        if (!status.ok()) {
            fprintf(stderr, "Verification failed: Key ");
            print_summary(key);
            fprintf(stderr, " missing from DB (status: %s)\n", status.ToString().c_str());
            return false;
        }
        if (actual_value != expected_value) {
            fprintf(stderr, "Verification failed: Value mismatch for key ");
            print_summary(key);
            fprintf(stderr, "\n  Expected: ");
            print_summary(expected_value);
            fprintf(stderr, "\n  Got:      ");
            print_summary(actual_value);
            fprintf(stderr, "\n");
            return false;
        }
    }

    std::unique_ptr<leveldb::Iterator> it(db->NewIterator(leveldb::ReadOptions()));
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        auto map_it = reference_map.find(key);
        if (map_it == reference_map.end()) {
            fprintf(stderr, "Verification failed: Unexpected key ");
            print_summary(key);
            fprintf(stderr, " found in DB with value ");
            print_summary(it->value().ToString());
            fprintf(stderr, "\n");
            return false;
        }
        if (map_it->second != it->value().ToString()) {
            fprintf(stderr, "Verification failed: Iterator value mismatch for key ");
            print_summary(key);
            fprintf(stderr, "\n  Expected: ");
            print_summary(map_it->second);
            fprintf(stderr, "\n  Got:      ");
            print_summary(it->value().ToString());
            fprintf(stderr, "\n");
            return false;
        }
    }
    return true;
}

}  // namespace


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    AutoDbDeleter db_deleter;

    FuzzedDataProvider fuzzed_data(data, size);
    std::unique_ptr<leveldb::DB> db = OpenDB(db_deleter.path(), fuzzed_data);
    if (!db.get()) {
        fprintf(stderr, "couldn't get db after open\n");
        assert(db.get());
    }

    std::map<std::string, std::string> reference_map;
    size_t total_size = 0;
    constexpr size_t max_size = 256 * 1024 * 1024;

    LIMITED_WHILE(fuzzed_data.remaining_bytes() != 0, 100, total_size, max_size) {
        FuzzOp fuzz_op = fuzzed_data.ConsumeEnum<FuzzOp>();

        switch (fuzz_op) {
        case FuzzOp::kPut: {
            std::string key = fuzzed_data.ConsumeRandomLengthString();
            std::string value = fuzzed_data.ConsumeRandomLengthString();
            if (fuzzed_data.ConsumeBool()) {
                value.resize(value.size() + fuzzed_data.ConsumeIntegralInRange<size_t>(0, 1024*1024*20));
                total_size += value.size();
            }
            leveldb::Status status = db->Put(leveldb::WriteOptions(), key, value);
            if (status.ok()) {
                reference_map[key] = value;
            } else {
                fprintf(stderr, "db->Put() failed: %s\n", status.ToString().c_str());
                assert(false);
            } 
            break;
        }   
        case FuzzOp::kDelete: {
            std::string key = fuzzed_data.ConsumeRandomLengthString();
            leveldb::Status status = db->Delete(leveldb::WriteOptions(), key);
            if (status.ok()) {
                reference_map.erase(key);
            } else {
                fprintf(stderr, "db->Delete() failed: %s\n", status.ToString().c_str());
                assert(false);
            }
            break;
        }
        case FuzzOp::kGet: {
            std::string key = fuzzed_data.ConsumeRandomLengthString();
            std::string value;
            db->Get(leveldb::ReadOptions(), key, &value);
            break;
        }
        case FuzzOp::kGetProperty: {
            std::string name = fuzzed_data.ConsumeRandomLengthString();
            std::string value;
            db->GetProperty(name, &value);
            break;
        }
        case FuzzOp::kIterate: {
            std::unique_ptr<leveldb::Iterator> it(db->NewIterator(leveldb::ReadOptions()));
            for (it->SeekToFirst(); it->Valid(); it->Next())
                continue;
            break;
        }
        case FuzzOp::kGetReleaseSnapshot: {
            leveldb::ReadOptions snapshot_options;
            snapshot_options.snapshot = db->GetSnapshot();
            std::unique_ptr<leveldb::Iterator> it(db->NewIterator(snapshot_options));
            db->ReleaseSnapshot(snapshot_options.snapshot);
            break;
        }
        case FuzzOp::kReopenDb: {
            db.reset();
            db = OpenDB(db_deleter.path(), fuzzed_data);
            if (!db) {
                fprintf(stderr, "couldn't reopen db\n");
                assert(db);
            }
            break;
        }
        case FuzzOp::kCompactRange: {
            std::string begin_key = fuzzed_data.ConsumeRandomLengthString();
            std::string end_key =  fuzzed_data.ConsumeRandomLengthString();
            leveldb::Slice begin_slice(begin_key);
            leveldb::Slice end_slice(end_key);
            db->CompactRange(&begin_slice, &end_slice);
            break;
        }
        case FuzzOp::kWrite: {
            leveldb::WriteBatch batch;
            std::map<std::string, std::optional<std::string>> batch_changes;
            size_t batch_size = 0;
    
            LIMITED_WHILE(fuzzed_data.ConsumeBool(), 100, total_size + batch_size, max_size) {
                std::string key = fuzzed_data.ConsumeRandomLengthString();
                if (fuzzed_data.ConsumeBool()) {
                    std::string value = fuzzed_data.ConsumeRandomLengthString();
                    if (fuzzed_data.ConsumeBool()) {
                        value.resize(value.size() + fuzzed_data.ConsumeIntegralInRange<size_t>(0, 1024*1024*20));
                    }
                    batch.Put(key, value);
                    batch_changes[key] = value;
                    batch_size += value.size();  
                } else {
                    batch.Delete(key);
                    batch_changes[key] = std::nullopt;  
                }
            }
    
            leveldb::WriteOptions write_options;
            write_options.sync = fuzzed_data.ConsumeBool();
            leveldb::Status status = db->Write(write_options, &batch);
      
            if (status.ok()) {
                total_size += batch_size;
                for (const auto& [key, value] : batch_changes) {
                    if (!value) {
                        reference_map.erase(key);
                    } else {
                        reference_map[key] = *value;
                    }
                }
            } else {
                fprintf(stderr, "db->Write() with batch failed: %s\n", status.ToString().c_str());
                assert(false);
            }
            break;
            }
        }
    }

  assert(VerifyContents(db.get(), reference_map));

  return 0;
}
