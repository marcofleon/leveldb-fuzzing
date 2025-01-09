#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <random>
#include <unordered_map>
#include <cassert>

#include "leveldb/db.h"
#include "leveldb/iterator.h"
#include "leveldb/options.h"
#include "leveldb/status.h"

#include "FuzzedDataProvider.h"

namespace {

// Deletes the database directory when going out of scope.
class AutoDbDeleter {
 public:
  AutoDbDeleter() {
    // Create a random directory name
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    
    db_path_ = std::string("/tmp/testdb_") + std::to_string(dis(gen));
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

// Returns nullptr (a falsey unique_ptr) if opening fails.
std::unique_ptr<leveldb::DB> OpenDB(const std::string& path) {
  leveldb::Options options;
  options.create_if_missing = true;

  leveldb::DB* db_ptr;
  leveldb::Status status = leveldb::DB::Open(options, path, &db_ptr);
  if (!status.ok())
    return nullptr;

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
  // Add new values here.

  // When adding new values, update to the last value above.
  kMaxValue = kCompactRange,
};

// Helper function to verify DB contents match the map
bool VerifyContents(leveldb::DB* db, const std::unordered_map<std::string, std::string>& reference_map) {
  // First check that every key-value in the map exists in leveldb
  for (const auto& [key, expected_value] : reference_map) {
    std::string actual_value;
    auto status = db->Get(leveldb::ReadOptions(), key, &actual_value);
    if (!status.ok() || actual_value != expected_value) {
      return false;
    }
  }

  // Then verify no extra keys exist in leveldb
  std::unique_ptr<leveldb::Iterator> it(db->NewIterator(leveldb::ReadOptions()));
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    auto map_it = reference_map.find(it->key().ToString());
    if (map_it == reference_map.end() || map_it->second != it->value().ToString()) {
      return false;
    }
  }

  return true;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  AutoDbDeleter db_deleter;

  std::unique_ptr<leveldb::DB> db = OpenDB(db_deleter.path());
  if (!db.get())
    return 0;

  // Create reference map to track expected contents
  std::unordered_map<std::string, std::string> reference_map;

  FuzzedDataProvider fuzzed_data(data, size);
  int counter = 100;
  while (fuzzed_data.remaining_bytes() != 0 && counter-- > 0) {
    FuzzOp fuzz_op = fuzzed_data.ConsumeEnum<FuzzOp>();

    switch (fuzz_op) {
    case FuzzOp::kPut: {
            
      std::string key = fuzzed_data.ConsumeRandomLengthString();
      std::string value = fuzzed_data.ConsumeRandomLengthString();
      if (fuzzed_data.ConsumeBool()) {
          value.resize(value.size() + fuzzed_data.ConsumeIntegralInRange<size_t>(0, 1024*1024*20));
      }
      db->Put(leveldb::WriteOptions(), key, value);
      reference_map[key] = value;
      break;
    }
    case FuzzOp::kDelete: {
      std::string key = fuzzed_data.ConsumeRandomLengthString();
      db->Delete(leveldb::WriteOptions(), key);
      reference_map.erase(key);
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
      std::unique_ptr<leveldb::Iterator> it(
          db->NewIterator(leveldb::ReadOptions()));
      for (it->SeekToFirst(); it->Valid(); it->Next())
        continue;
    }
    case FuzzOp::kGetReleaseSnapshot: {
      leveldb::ReadOptions snapshot_options;
      snapshot_options.snapshot = db->GetSnapshot();
      std::unique_ptr<leveldb::Iterator> it(db->NewIterator(snapshot_options));
      db->ReleaseSnapshot(snapshot_options.snapshot);
    }
    case FuzzOp::kReopenDb: {
     
      
      db.reset();
      db = OpenDB(db_deleter.path());
      if (!db)
        return 0;
      
      
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
    }
  }

  // Verify final contents match
  assert(VerifyContents(db.get(), reference_map));

  return 0;
}
