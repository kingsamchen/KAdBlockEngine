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

}   // namespace abe