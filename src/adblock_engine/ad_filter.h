/*
 @ 0xCCCCCCCC
*/

#if defined(_MSC_VER)
#pragma once
#endif

#ifndef KADBLOCKENGINE_ADBLOCK_ENGINE_AD_FILTER_H_
#define KADBLOCKENGINE_ADBLOCK_ENGINE_AD_FILTER_H_

#include <set>
#include <unordered_map>
#include <vector>

#include "kbase/basic_macros.h"
#include "kbase/path.h"
#include "kbase/string_view.h"

namespace abe {

// Third-party option mode.
enum class ThirdParty {
    NOT_SPECIFIED,
    EXCLUSIVE,
    EXCLUDED
};

struct Rule {
    bool match_case;
    ThirdParty third_party;
    unsigned int content_type;
    std::string domains;
    std::string text;   // The text contains no qualifiers(such as, exception prefix and options).

    explicit Rule(std::string rule_text);
};

struct ElemHideRule {
    std::string text;   // The text contains no domains.

    explicit ElemHideRule(std::string rule_text);
};

struct ElemHideRuleHash {
    size_t operator()(const ElemHideRule& rule) const
    {
        return std::hash<std::string>()(rule.text);
    }
};

inline bool operator==(const ElemHideRule& lhs, const ElemHideRule& rhs)
{
    return lhs.text == rhs.text;
}

using RuleMap = std::unordered_map<std::string, std::vector<Rule>>;
using ElemHideRuleMap = std::unordered_map<ElemHideRule, std::set<std::string>, ElemHideRuleHash>;

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

    void AddRule(kbase::StringView rule);

private:
    Info info_;
    RuleMap blocking_rules_;
    RuleMap exception_rules_;
    ElemHideRuleMap elem_hide_rules_;
    ElemHideRuleMap exception_elem_hide_rules_;
};

class LoadingFilterError : public std::runtime_error {
public:
    explicit LoadingFilterError(const char* message);

    explicit LoadingFilterError(const std::string& message);
};

}   // namespace abe

#endif  // KADBLOCKENGINE_ADBLOCK_ENGINE_AD_FILTER_H_