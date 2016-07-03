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
#include "kbase/pickle.h"
#include "kbase/string_view.h"

namespace abe {

enum class MatchResult {
    NOT_MATCHED,
    BLOCKING_MATCHED,
    EXCEPTION_MATCHED
};

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
    bool transformed;   // Has the `text` been transformed into a regex literal.
    std::string text;   // The `text` contains no qualifiers(e.g. exception prefix and options).

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

inline bool operator<(const ElemHideRule& lhs, const ElemHideRule& rhs)
{
    return lhs.text < rhs.text;
}

// RuleMap: keyword -> a list of rules.
// ElemHideRuleMap: rule -> a set of domains.
using RuleMap = std::unordered_map<std::string, std::vector<Rule>>;
using ElemHideRuleMap = std::unordered_map<ElemHideRule, std::vector<std::string>,
                                           ElemHideRuleHash>;

// An AdFilter instance represents a subscribed filter stored in a physical file on the disk.
// Each AdFilter instance is identified by the path of the rule file.
class AdFilter {
public:
    struct Info {
        std::string version;
        std::string title;
        std::string last_modified;
    };

    explicit AdFilter(const kbase::Path& filter_file_path);

    AdFilter(AdFilter&& other) = default;

    ~AdFilter() = default;

    AdFilter& operator=(AdFilter&& rhs) = default;

    DISALLOW_COPY(AdFilter);

    static AdFilter FromSnapshot(kbase::PickleReader& snapshot);

    MatchResult MatchAny(const std::string& request_url,
                         const std::string& request_domain,
                         unsigned int content_type,
                         bool third_party);

    // We can't just return filtered element hide rules, because there may be some rules that
    // would be inverted by exception rules in other filters.
    void FetchElementHideRules(const std::string& request_domain, std::set<ElemHideRule>& rules,
                               std::set<ElemHideRule>& exception_rules) const;

    const Info& GetFilterInfo() const;

    kbase::Pickle TakeSnapshot() const;

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