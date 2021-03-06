/*
 @ 0xCCCCCCCC
*/

#include "adblock_engine/ad_filter_manager.h"

#include <fstream>

#include "kbase/file_util.h"
#include "kbase/logging.h"
#include "kbase/md5.h"

namespace {

constexpr const wchar_t kSnapshotFileExtension[] = L".abx";

}   // namespace

namespace abe {

void AdFilterManager::LoadAdFilter(const kbase::Path& filter_file)
{
    kbase::Path snapshot_file(filter_file);
    snapshot_file.ReplaceExtension(kSnapshotFileExtension);
    if (kbase::PathExists(snapshot_file)) {
        std::string file_data = kbase::ReadFileToString(snapshot_file);
        if (!file_data.empty()) {
            kbase::MD5Digest checksum;
            auto snapshot_data = file_data.data() + sizeof(checksum);
            auto snapshot_data_size = file_data.size() - sizeof(checksum);
            kbase::MD5Sum(snapshot_data, snapshot_data_size, &checksum);
            if (memcmp(checksum.data(), file_data.data(), sizeof(checksum)) == 0) {
                kbase::PickleReader snapshot(snapshot_data, snapshot_data_size);
                AdFilter ad_filter = AdFilter::FromSnapshot(snapshot);
                ad_filters_.push_back(AdFilterPair(filter_file, std::move(ad_filter)));
                return;
            }
        }
    }

    // Yeah, we don't check if there was duplicate adfilters.
    ad_filters_.push_back(AdFilterPair(filter_file, AdFilter(filter_file)));
}

void AdFilterManager::UnloadAdFilter(const kbase::Path& filter_file)
{
    auto it = std::remove_if(ad_filters_.begin(), ad_filters_.end(),
                             [&filter_file](const auto& filter_pair) {
        return filter_file == filter_pair.first;
    });

    ad_filters_.erase(it, ad_filters_.end());
}

bool AdFilterManager::ShouldBlockRequest(const std::string& request_url,
                                         const std::string& request_domain,
                                         unsigned content_type,
                                         bool third_party) const
{
    bool blocking_rule_hit = false;
    for (const auto& filter_pair : ad_filters_) {
        // Logically, filter here is still constness, with respect the manager;
        // but we have to cast its bitwise constness away.
        AdFilter& filter = const_cast<AdFilter&>(filter_pair.second);
        auto result = filter.MatchAny(request_url, request_domain, content_type, third_party);
        if (result == MatchResult::BLOCKING_MATCHED) {
            blocking_rule_hit = true;
        } else if (result == MatchResult::EXCEPTION_MATCHED) {
            return false;
        }
    }

    return blocking_rule_hit;
}

std::string AdFilterManager::GetElementHideContent(const std::string& request_domain) const
{
    constexpr const kbase::StringView kJoinDelim(", ", 2);

    std::set<ElemHideRule> rules;
    std::set<ElemHideRule> exception_rules;
    for (const auto& filter_pair : ad_filters_) {
        filter_pair.second.FetchElementHideRules(request_domain, rules, exception_rules);
    }

    std::string element_hide_rule;
    element_hide_rule.reserve(rules.size() - exception_rules.size());
    for (auto it = rules.begin(); it != rules.end(); ++it) {
        if (exception_rules.count(*it) == 0) {
            element_hide_rule.append(it->text).append(kJoinDelim.data());
        }
    }

    // Get rid of tailing `, `.
    element_hide_rule.resize(element_hide_rule.length() - kJoinDelim.length());
    return element_hide_rule;
}

void AdFilterManager::SnapshotAdFilter(const kbase::Path& filter_file) const
{
    auto it = std::find_if(ad_filters_.cbegin(), ad_filters_.cend(),
                           [&filter_file](const auto& pair) {
                               return pair.first == filter_file;
                           });
    if (it == ad_filters_.cend()) {
        return;
    }

    kbase::Pickle&& snapshot = it->second.TakeSnapshot();
    kbase::MD5Digest checksum;
    kbase::MD5Sum(snapshot.data(), snapshot.size(), &checksum);

    kbase::Path snapshot_file(filter_file);
    snapshot_file.ReplaceExtension(kSnapshotFileExtension);
    std::ofstream out(snapshot_file.value(), std::ios::binary);
    if (!out) {
        LOG(WARNING) << "Failed to create snapshot file for " << snapshot_file.AsUTF8();
        return;
    }

    out.write(reinterpret_cast<const char*>(checksum.data()), checksum.size());
    out.write(static_cast<const char*>(snapshot.data()), snapshot.size());
}

}   // namespace abe