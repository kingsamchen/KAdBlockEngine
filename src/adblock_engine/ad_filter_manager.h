/*
 @ 0xCCCCCCCC
*/

#if defined(_MSC_VER)
#pragma once
#endif

#ifndef KADBLOCKENGINE_ADBLOCK_ENGINE_AD_FILTER_MANAGER_H_
#define KADBLOCKENGINE_ADBLOCK_ENGINE_AD_FILTER_MANAGER_H_

#include <vector>

#include "kbase/basic_macros.h"
#include "kbase/path.h"

#include "adblock_engine/ad_filter.h"

namespace abe {

class AdFilterManager {
public:
    AdFilterManager() = default;

    ~AdFilterManager() = default;

    DISALLOW_COPY(AdFilterManager);

    DISALLOW_MOVE(AdFilterManager);

    void LoadAdFilter(const kbase::Path& filter_file);

    void UnloadAdFilter(const kbase::Path& filter_file);

    bool ShouldBlockRequest(const std::string& request_url,
                            const std::string& request_domain,
                            unsigned int content_type,
                            bool third_party) const;

    std::string GetElementHideContent(const std::string& request_domain) const;

    // Creates a snapshot file on disk for the AdFilter indicated by `filter_file`.
    void SnapshotAdFilter(const kbase::Path& filter_file) const;

private:
    using AdFilterPair = std::pair<kbase::Path, AdFilter>;
    std::vector<AdFilterPair> ad_filters_;
};

}   // namespace abe

#endif  // KADBLOCKENGINE_ADBLOCK_ENGINE_AD_FILTER_MANAGER_H_