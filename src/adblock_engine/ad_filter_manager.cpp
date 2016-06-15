/*
 @ 0xCCCCCCCC
*/

#include "adblock_engine/ad_filter_manager.h"

namespace abe {

void AdFilterManager::LoadAdFilter(const kbase::Path& filter_file_path)
{
    // Yeah, we don't check if there was duplicate adfilters.
    ad_filters_.push_back(AdFilterPair(filter_file_path, AdFilter(filter_file_path)));
}

void AdFilterManager::UnloadAdFilter(const kbase::Path& filter_file_path)
{
    auto it = std::remove_if(ad_filters_.begin(), ad_filters_.end(),
                             [&filter_file_path](const auto& filter_pair) {
        return filter_file_path == filter_pair.first;
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

}   // namespace abe