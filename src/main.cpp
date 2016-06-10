/*
 @ 0xCCCCCCCC
*/

#include <conio.h>

#include <iostream>

#include "kbase/error_exception_util.h"

#include "adblock_engine/ad_filter.h"

void TestAdFilterMatchAny(abe::AdFilter& ad_filter)
{
    auto rv = ad_filter.MatchAny("test.kc.cn/js/ads/demo.js", "test.kc.cn", 2, false);
    ENSURE(CHECK, rv == abe::MatchResult::BLOCKING_MATCHED)(static_cast<unsigned>(rv)).Require();
    std::cout << "-> " << __FUNCTION__ << " passed\n";
}

void TestAdFilterElementHide(const abe::AdFilter& ad_filter)
{
    std::set<abe::ElemHideRule> rules, exception_rules;
    ad_filter.FetchElementHideRules("cndesign.com", rules, exception_rules);
    ENSURE(CHECK, rules.size() > 0 && exception_rules.size() > 0)
          (rules.size())(exception_rules.size()).Require();
    std::cout << "-> " << __FUNCTION__ << " passed\n";
}

int main()
{
    kbase::Path filter_path(LR"(C:\Projects\KAdBlockEngine\src\test\easylistchina.txt)");
    abe::AdFilter ad_filter(filter_path);
    TestAdFilterMatchAny(ad_filter);
    TestAdFilterElementHide(ad_filter);
    _getch();
    return 0;
}