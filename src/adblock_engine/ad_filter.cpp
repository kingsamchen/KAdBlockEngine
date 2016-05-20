/*
 @ 0xCCCCCCCC
*/

#include "adblock_engine/ad_filter.h"

#include <map>
#include <regex>
#include <tuple>

#include "kbase/error_exception_util.h"
#include "kbase/file_util.h"
#include "kbase/string_util.h"
#include "kbase/tokenizer.h"

namespace {

using abe::Rule;
using abe::RuleMap;
using abe::ThirdParty;

using StringViewPair = std::tuple<kbase::StringView, kbase::StringView>;

constexpr const char kVersionTagName[] = "Version";
constexpr const char kTitleTagName[] = "Title";
constexpr const char kLastModifiedTagName[] = "Last Modified";

const std::regex kRuleKeywordRegexPat("[^a-z0-9%*][a-z0-9%]{3,}(?=[^a-z0-9%*])",
                                      std::regex_constants::ECMAScript |
                                      std::regex_constants::optimize);

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

// Returns a pair that contains domains the rule applies on, delimited by `delim`.
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

// Make sure that `rule_text` doesn't have either @@ prefix, or options part.
std::string FindRuleKeyword(const std::string& rule_text, const RuleMap& rule_set)
{
    std::string keyword;

    // We don't need a keyword for a regular expression rule.
    if (rule_text.front() == '/' && rule_text.back() == '/') {
        return keyword;
    }

    size_t keyword_rule_count = static_cast<size_t>(-1);
    size_t keyword_length = 0U;
    std::sregex_iterator candidate_it(rule_text.begin(), rule_text.end(), kRuleKeywordRegexPat);
    std::sregex_iterator end;
    for (; candidate_it != end; ++candidate_it) {
        auto&& candidate = candidate_it->str(0);
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

}   // namespace

namespace abe {

Rule::Rule(std::string rule_text)
    : match_case(false),
      third_party(ThirdParty::NOT_SPECIFIED),
      content_type(kDefaultContentType),
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
                        exception_elem_hide_rules_[rule].insert(domain.ToString());
                    }
                } else {
                    elem_hide_rules_[rule].insert(domain.ToString());
                }
            }
        } else {
            // It's meaningless for an unconditional rule being an exception rule.
            if (!is_exception) {
                elem_hide_rules_[rule].insert("");
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

LoadingFilterError::LoadingFilterError(const char* message)
    : runtime_error(message)
{}

LoadingFilterError::LoadingFilterError(const std::string& message)
    : runtime_error(message)
{}

}   // namespace abe