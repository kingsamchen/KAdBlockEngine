/*
 @ 0xCCCCCCCC
*/

#include "adblock_engine/ad_filter.h"

#include "kbase/error_exception_util.h"
#include "kbase/file_util.h"
#include "kbase/string_util.h"
#include "kbase/tokenizer.h"

namespace {

const char kVersionTagName[] = "Version";
const char kTitleTagName[] = "Title";
const char kLastModifiedTagName[] = "Last Modified";

bool IsComment(kbase::StringView line)
{
    return kbase::StartsWith(line, "!") || kbase::StartsWith(line, "[");
}

bool IsExceptionRule(kbase::StringView line)
{
    return kbase::StartsWith(line, "@@");
}

}   // namespace

namespace abe {

AdFilter::AdFilter(const kbase::Path& filter_file_path)
{
    std::string filter_data = kbase::ReadFileToString(filter_file_path);
    // TODO: throw our own exception type.
    ENSURE(RAISE, !filter_data.empty()).Require();
    kbase::Tokenizer data_lines(filter_data, "\r\n");
    for (auto&& line : data_lines) {
        if (line.empty()) {
            continue;
        }

        if (IsComment(line)) {
            LoadFilterInfo(line);
            continue;
        }

        if (IsExceptionRule(line)) {

        } else {

        }

        // TODO: add to rule list.
    }
}

const AdFilter::Info& AdFilter::GetFilterInfo() const
{
    return info_;
}

void AdFilter::LoadFilterInfo(kbase::StringView comment)
{
    auto colon_pos = comment.find(':');
    if (colon_pos == kbase::StringView::npos) {
        return;
    }

    auto info_tag = comment.substr(2, colon_pos - 2);
    if (info_tag == kVersionTagName) {
        info_.version = comment.substr(colon_pos + 2).ToString();
    } else if (info_tag == kTitleTagName) {
        info_.title = comment.substr(colon_pos + 2).ToString();
    } else if (info_tag == kLastModifiedTagName) {
        info_.last_modified = comment.substr(colon_pos + 2).ToString();
    }
}

}   // namespace abe