/*
 @ 0xCCCCCCCC
*/

#if defined(_MSC_VER)
#pragma once
#endif

#ifndef KADBLOCKENGINE_ADBLOCK_ENGINE_AD_FILTER_H_
#define KADBLOCKENGINE_ADBLOCK_ENGINE_AD_FILTER_H_

#include "kbase/basic_macros.h"
#include "kbase/path.h"
#include "kbase/string_view.h"

namespace abe {

class AdFilter {
public:
    struct Info {
        std::string version;
        std::string title;
        std::string last_modified;
    };

    explicit AdFilter(const kbase::Path& filter_file_path);

    ~AdFilter() = default;

    DISALLOW_COPY(AdFilter);

    const Info& GetFilterInfo() const;

private:
    void LoadFilterInfo(kbase::StringView comment);

private:
    Info info_;
};

}   // namespace abe

#endif  // KADBLOCKENGINE_ADBLOCK_ENGINE_AD_FILTER_H_