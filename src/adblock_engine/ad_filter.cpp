/*
 @ 0xCCCCCCCC
*/

#include "adblock_engine/ad_filter.h"

#include <algorithm>
#include <map>
#include <regex>
#include <tuple>

#include "kbase/error_exception_util.h"
#include "kbase/file_util.h"
#include "kbase/string_util.h"
#include "kbase/tokenizer.h"

namespace {

using abe::AdFilter;
using abe::Rule;
using abe::RuleMap;
using abe::ThirdParty;

using StringViewPair = std::tuple<kbase::StringView, kbase::StringView>;

constexpr const char kVersionTagName[] = "Version";
constexpr const char kTitleTagName[] = "Title";
constexpr const char kLastModifiedTagName[] = "Last Modified";

constexpr const auto kOptFlag = std::regex_constants::ECMAScript | std::regex_constants::optimize;

const std::regex kRuleKeywordRegexPat("[^a-z0-9%*][a-z0-9%]{3,}(?=[^a-z0-9%*])", kOptFlag);
const std::regex kURLKeywordRegexPat("[a-z0-9%]{3,}", kOptFlag);
const std::regex kEscapeSpecialSymbolPat("\\W", kOptFlag);

enum ContentType : unsigned int {
    OTHER = 1U << 0,
    XBL = 1U << 0,
    DTD = 1U << 0,
    SCRIPT = 1U << 1,
    IMAGE = 1U << 2,
    STYLESHEET = 1U << 3,
    OBJECT = 1U << 4,
    SUBDOCUMENT = 1U << 5,
    DOCUMENT = 1U << 6,
    PING = 1U << 10,
    XMLHTTPREQUEST = 1U << 11,
    OBJECT_SUBREQUEST = 1U << 12,
    MEDIA = 1U << 14,
    FONT = 1U << 15,
    BACKGROUND = 1U << 2,
    POPUP = 1U << 28,
    GENERICBLOCK = 1U << 29,
    ELEMHIDE = 1U << 30,
    GENERICHIDE = 1U << 31
};

constexpr const unsigned int kDefaultContentType = 0x7FFFFFFF & ~(ContentType::DOCUMENT |
                                                                  ContentType::ELEMHIDE |
                                                                  ContentType::POPUP |
                                                                  ContentType::GENERICHIDE |
                                                                  ContentType::GENERICBLOCK);

const std::map<kbase::StringView, unsigned int> kContentTypeMap {
    { "other", ContentType::OTHER },
    { "xbl", ContentType::XBL },
    { "dtd", ContentType::DTD },
    { "script", ContentType::SCRIPT },
    { "image", ContentType::IMAGE },
    { "stylesheet", ContentType::STYLESHEET },
    { "object", ContentType::OBJECT },
    { "subdocument", ContentType::SUBDOCUMENT },
    { "document", ContentType::DOCUMENT },
    { "ping", ContentType::PING },
    { "xmlhttprequest", ContentType::XMLHTTPREQUEST },
    { "object_subrequest", ContentType::OBJECT_SUBREQUEST },
    { "media", ContentType::MEDIA },
    { "font", ContentType::FONT },
    { "background", ContentType::BACKGROUND }, // For backwards compat, same as `image`.
    { "popup", ContentType::POPUP },
    { "genericblock", ContentType::GENERICBLOCK },
    { "elemhide", ContentType::ELEMHIDE },
    { "generichide", ContentType::GENERICHIDE }
};

bool IsComment(kbase::StringView line)
{
    return kbase::StartsWith(line, "!") || kbase::StartsWith(line, "[");
}

bool IsElemHideRule(kbase::StringView line)
{
    return line.find('#') != kbase::StringView::npos;
}

bool IsExceptionRule(kbase::StringView rule)
{
    return kbase::StartsWith(rule, "@@");
}

bool IsExceptionElemHideRule(kbase::StringView rule)
{
    return rule.find("#@#") != kbase::StringView::npos;
}

bool IsRegexRuleText(const std::string& rule_text)
{
    return rule_text.front() == '/' && rule_text.back() == '/';
}

// Make sure that `rule_text` doesn't prefix with @@.
StringViewPair SplitRuleOptions(kbase::StringView rule_text)
{
    auto delim_pos = rule_text.rfind('$');
    // A regular expression itself may contain `$`.
    if (rule_text[0] == '/' && rule_text.rfind('/') > delim_pos) {
        return std::make_tuple(rule_text, kbase::StringView());
    }

    auto rule = rule_text.substr(0, delim_pos);
    auto options = delim_pos == kbase::StringView::npos ? kbase::StringView() :
                                                          rule_text.substr(delim_pos + 1);
    return std::make_tuple(rule, options);
}

// Returns a pair that contains domains the rule applies on.
// Note that `domains` may be empty.
StringViewPair SplitOptionDomain(kbase::StringView field)
{
    auto delim_pos = field.find('=');
    auto domain_tag = field.substr(0, delim_pos);
    auto domains = delim_pos == kbase::StringView::npos ? kbase::StringView() :
                                                          field.substr(delim_pos + 1);
    return std::make_tuple(domain_tag, domains);
}

// Returns a pair of element hide rule text and its restricted domains.
// Note that domains may be empty.
StringViewPair SplitElemHideDomains(kbase::StringView rule_text, bool is_exception)
{
    kbase::StringView tag = is_exception ? "#@#" : "##";
    auto tag_start_pos = rule_text.find(tag);
    auto domains = rule_text.substr(0, tag_start_pos);
    auto rule = rule_text.substr(tag_start_pos + tag.length());

    return std::make_tuple(domains, rule);
}

void ParseRuleOptions(kbase::StringView option_text, Rule& rule)
{
    std::string lower_option_text = kbase::StringToLowerASCII(option_text.ToString());
    kbase::Tokenizer options(lower_option_text, ",");
    for (auto&& option : options) {
        if (option == "match-case") {
            rule.match_case = true;
        } else if (option == "third-party") {
            rule.third_party = ThirdParty::EXCLUSIVE;
        } else if (option == "~third-party") {
            rule.third_party = ThirdParty::EXCLUDED;
        } else if (kContentTypeMap.count(option) > 0) {
            if (rule.content_type == kDefaultContentType) {
                rule.content_type = 0U;
            }

            rule.content_type |= kContentTypeMap.at(option);
        } else if (option[0] == '~' && kContentTypeMap.count(option.substr(1))) {
            rule.content_type &= ~(kContentTypeMap.at(option.substr(1)));
        } else if (kbase::StartsWith(option, "domain")) {
            kbase::StringView domains;
            std::tie(std::ignore, domains) = SplitOptionDomain(option);
            if (!domains.empty()) {
                rule.domains = domains.ToString();
            }
        }
    }
}

// Returns a keyword (may be an empty string) for fast locating the rule.
// Make sure that `rule_text` doesn't have either @@ prefix, or options part.
std::string FindRuleKeyword(const std::string& rule_text, const RuleMap& rule_set)
{
    std::string keyword;

    // We always use an empty string as the keyword for a regular expression rule.
    // Afterall, there are only a few of them.
    if (IsRegexRuleText(rule_text)) {
        return keyword;
    }

    // If the rule text is too short to find a representative keyword, fallback to
    // an empty string.
    size_t keyword_rule_count = static_cast<size_t>(-1);
    size_t keyword_length = 0U;
    std::sregex_iterator candidate_it(rule_text.begin(), rule_text.end(), kRuleKeywordRegexPat);
    std::sregex_iterator end;
    for (; candidate_it != end; ++candidate_it) {
        auto&& candidate = candidate_it->str(0).substr(1);
        size_t count = rule_set.count(candidate) > 0 ? rule_set.at(candidate).size() : 0;
        if (count < keyword_rule_count ||
            (count == keyword_rule_count && candidate.length() > keyword_length)) {
            keyword_rule_count = count;
            keyword_length = candidate.length();
            keyword = std::move(candidate);
        }
    }

    return keyword;
}

// Transform the rule text into an equivalent regex literal.
// Since this process may cost, we keep the outcome for subsequent uses.
void TransformRule(Rule& rule)
{
    // The transformation would be done in either way.
    rule.transformed = true;
    std::string& text = rule.text;

    if (IsRegexRuleText(text)) {
        text = text.substr(1, text.length() - 2);
        return;
    }

    // Try not to use regex to do replacement unless we have to.

    // Remove multiple wildcards.
    text.erase(std::unique(text.begin(), text.end(), [](const char& lch, const char& rch) {
        return lch == '*' && rch == '*';
    }), text.end());

    // Remove anchors following separator placeholder.
    if (kbase::EndsWith(text, "^|")) {
        text.pop_back();
    }

    // Escape special symbols.
    text = std::regex_replace(text, kEscapeSpecialSymbolPat, "\\$&");

    // Replace wildcards by `.*`.
    kbase::ReplaceSubstring(text, "\\*", ".*");

    // Process separator placeholders (all ANSI characters but alphanumeric characters and _%.-).
    kbase::ReplaceSubstring(text, "\\^", "(?:[\\x00-\\x24\\x26-\\x2C\\x2F\\x3A-\\x40\\x5B-\\x5E\\x60\\x7B-\\x7F]|$)");
    if (kbase::StartsWith(text, "\\|\\|")) {
        kbase::ReplaceSubstring(text, "\\|\\|", "^[\\w\\-]+:\\/+(?!\\/)(?:[^\\/]+\\.)?", 0, false);
    }

    // Process anchor at expression start.
    if (kbase::StartsWith(text, "\\|")) {
        kbase::ReplaceSubstring(text, "\\|", "^", 0, false);
    }

    // Process anchor at expression end.
    if (kbase::EndsWith(text, "\\|")) {
        kbase::ReplaceSubstring(text, "\\|", "$", text.length() - 2);
    }

    // Remove leading wildcards.
    if (kbase::StartsWith(text, ".*")) {
        kbase::ReplaceSubstring(text, ".*", "", 0, false);
    }

    // Remove trailing wildcards.
    if (kbase::EndsWith(text, ".*")) {
        kbase::ReplaceSubstring(text, ".*", "", text.length() - 2);
    }
}

// Returns true, if `test_domain` represents the same domain as `criteria_domain`.
// Returns false, otherwise.
bool IsSameDomainAs(kbase::StringView test_domain, kbase::StringView criteria_domain)
{
    if (kbase::EndsWith(test_domain, criteria_domain, false)) {
        auto length_diff = test_domain.length() - criteria_domain.length();
        if (length_diff > 0) {
            if (test_domain[length_diff - 1] == '.') {
                return true;
            }
        } else {
            return true;
        }
    }

    return false;
}

bool ApplyOnContentType(const Rule& rule, unsigned int request_content_type)
{
    // If the user of the engine has another set of content type definition,
    // then you should provide your own mapping here.
    return (rule.content_type & request_content_type) != 0;
}

bool ApplyOnThirdParty(const Rule& rule, bool third_party)
{
    bool matched = false;
    switch (rule.third_party) {
        case ThirdParty::NOT_SPECIFIED:
            matched = true;
            break;

        case ThirdParty::EXCLUSIVE:
            matched = third_party;
            break;

        case ThirdParty::EXCLUDED:
            matched = !third_party;
            break;

        default:
            ENSURE(CHECK, kbase::NotReached()).Require();
    }

    return matched;
}

bool ApplyOnDomain(const Rule& rule, const std::string& request_domain)
{
    // No domain restrictions. The domain option of the rule is always applied.
    if (rule.domains.empty()) {
        return true;
    }

    std::vector<std::string> domains;
    kbase::SplitString(rule.domains, "|", domains);

    // Inverted domains have higher precedence.
    std::partition(domains.begin(), domains.end(), [](const auto& domain) {
        return domain[0] == '~';
    });

    for (const auto& domain : domains) {
        bool inversed = false;
        kbase::StringView domain_view(domain);
        if (domain_view[0] == '~') {
            inversed = true;
            domain_view.RemovePrefix(1);
        }

        if (IsSameDomainAs(request_domain, domain_view)) {
            return !inversed;
        }
    }

    return false;
}

bool ApplyOnURL(Rule& rule, const std::string& request_url)
{
    if (!rule.transformed) {
        TransformRule(rule);
    }

    auto flag = std::regex_constants::ECMAScript;
    if (!rule.match_case) {
        flag |= std::regex_constants::icase;
    }

    std::regex rule_pat(rule.text, flag);
    bool matched = std::regex_search(request_url, rule_pat);

    return matched;
}

// Returns true, if the `rule` applies to the `request_url`.
// Returns false, otherwise.
bool CheckRuleApply(Rule& rule, const std::string& request_url, const std::string& request_domain,
                    unsigned int content_type, bool third_pary)
{
    return  ApplyOnContentType(rule, content_type) &&
            ApplyOnThirdParty(rule, third_pary) &&
            ApplyOnDomain(rule, request_domain) &&
            ApplyOnURL(rule, request_url);
}

// Returns true, if there is a rule in the `rule_set` matches the `request_url`.
// Returns false, otherwise.
bool CheckRuleMatch(RuleMap& rule_set, const std::string& keyword, const std::string& request_url,
                    const std::string& request_domain, unsigned int content_type, bool third_pary)
{
    auto it = rule_set.find(keyword);
    if (it == rule_set.end()) {
        return false;
    }

    auto& rules = it->second;
    for (Rule& rule : rules) {
        if (CheckRuleApply(rule, request_url, request_domain, content_type, third_pary)) {
            return true;
        }
    }

    return false;
}

}   // namespace

namespace abe {

kbase::Pickle& operator<<(kbase::Pickle& pickle, const AdFilter::Info& filter_info)
{
    pickle << filter_info.version
           << filter_info.title
           << filter_info.last_modified;
    return pickle;
}

kbase::Pickle& operator<<(kbase::Pickle& pickle, const Rule& rule)
{
    pickle << rule.match_case
           << static_cast<unsigned int>(rule.third_party)
           << rule.content_type
           << rule.domains
           << rule.transformed
           << rule.text;
    return pickle;
}

kbase::Pickle& operator<<(kbase::Pickle& pickle, const ElemHideRule& elem_hide)
{
    pickle << elem_hide.text;
    return pickle;
}

Rule::Rule(std::string rule_text)
    : match_case(false),
      third_party(ThirdParty::NOT_SPECIFIED),
      content_type(kDefaultContentType),
      transformed(false),
      text(std::move(rule_text))
{}

ElemHideRule::ElemHideRule(std::string rule_text)
    : text(std::move(rule_text))
{}

AdFilter::AdFilter(const kbase::Path& filter_file_path)
{
    std::string filter_data = kbase::ReadFileToString(filter_file_path);
    ENSURE(RAISE, !filter_data.empty()).Require<LoadingFilterError>();
    kbase::Tokenizer data_lines(filter_data, "\r\n");
    for (auto&& line : data_lines) {
        if (line.empty()) {
            continue;
        }

        if (IsComment(line)) {
            LoadFilterInfo(line);
            continue;
        }

        AddRule(line);
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

void AdFilter::AddRule(kbase::StringView rule_text)
{
    bool is_exception = false;
    if (IsElemHideRule(rule_text)) {
        if (IsExceptionElemHideRule(rule_text)) {
            is_exception = true;
        }

        kbase::StringView domains;
        std::tie(domains, rule_text) = SplitElemHideDomains(rule_text, is_exception);
        ElemHideRule rule(rule_text.ToString());
        if (!domains.empty()) {
            kbase::Tokenizer domain_tokens(domains, ",");
            for (auto&& domain : domain_tokens) {
                if (is_exception) {
                    if (domain[0] != '~') {
                        exception_elem_hide_rules_[rule].push_back(domain.ToString());
                    }
                } else {
                    elem_hide_rules_[rule].push_back(domain.ToString());
                }
            }
        } else {
            // It's meaningless for an unconditional rule being an exception rule.
            if (!is_exception) {
                elem_hide_rules_[rule].push_back("");
            }
        }
    } else {
        if (IsExceptionRule(rule_text)) {
            rule_text.RemovePrefix(2);
            is_exception = true;
        }

        kbase::StringView option_text;
        std::tie(rule_text, option_text) = SplitRuleOptions(rule_text);
        Rule rule(rule_text.ToString());
        if (!option_text.empty()) {
            ParseRuleOptions(option_text, rule);
        }

        RuleMap& target_rule_set = is_exception ? exception_rules_ : blocking_rules_;
        std::string keyword = FindRuleKeyword(rule.text, target_rule_set);
        target_rule_set[keyword].push_back(std::move(rule));
    }
}

MatchResult AdFilter::MatchAny(const std::string& request_url, const std::string& request_domain,
                               unsigned int content_type, bool third_party)
{
    std::vector<std::string> candidates;
    std::sregex_iterator token_it(request_url.begin(), request_url.end(), kURLKeywordRegexPat);
    std::transform(token_it, std::sregex_iterator(), std::back_inserter(candidates),
                   [](const auto& match)->std::string {
        return match.str(0);
    });

    // Don't forget rules that associate with the empty keyword.
    candidates.push_back(std::string());

    for (const auto& candidate : candidates) {
        if (CheckRuleMatch(exception_rules_, candidate, request_url, request_domain, content_type,
                           third_party)) {
            return MatchResult::EXCEPTION_MATCHED;
        }

        if (CheckRuleMatch(blocking_rules_, candidate, request_url, request_domain, content_type,
                           third_party)) {
            return MatchResult::BLOCKING_MATCHED;
        }
    }

    return MatchResult::NOT_MATCHED;
}

void AdFilter::FetchElementHideRules(const std::string& request_domain,
                                     std::set<ElemHideRule>& rules,
                                     std::set<ElemHideRule>& exception_rules) const
{
    for (const auto& rule_pair : elem_hide_rules_) {
        // If the same rule already exists in another filter,
        // we skip it regradless of whether associated domains are the same.
        if (rules.count(rule_pair.first) == 0) {
            const auto& domains = rule_pair.second;
            if (std::any_of(domains.cbegin(), domains.cend(),
                            [&request_domain](const auto& domain) {
                return domain.empty() || IsSameDomainAs(request_domain, domain);
            })) {
                rules.insert(rule_pair.first);
            }
        }
    }

    for (const auto& rule_pair : exception_elem_hide_rules_) {
        if (exception_rules.count(rule_pair.first) == 0) {
            const auto& domains = rule_pair.second;
            if (std::any_of(domains.cbegin(), domains.cend(),
                            [&request_domain](const auto& domain) {
                return IsSameDomainAs(request_domain, domain);
            })) {
                exception_rules.insert(rule_pair.first);
            }
        }
    }
}

kbase::Pickle AdFilter::TakeSnapshot() const
{
    kbase::Pickle snapshot;

    snapshot << info_;
    snapshot << blocking_rules_ << exception_rules_;
    snapshot << elem_hide_rules_ << exception_elem_hide_rules_;

    return snapshot;
}

LoadingFilterError::LoadingFilterError(const char* message)
    : runtime_error(message)
{}

LoadingFilterError::LoadingFilterError(const std::string& message)
    : runtime_error(message)
{}

}   // namespace abe