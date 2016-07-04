/*
 @ 0xCCCCCCCC
*/

#include <conio.h>

#include <iostream>

#include "kbase/error_exception_util.h"
#include "kbase/file_util.h"
#include "kbase/md5.h"

#include "adblock_engine/ad_filter.h"
#include "adblock_engine/ad_filter_manager.h"

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

void TestAdFilterSerialization(const kbase::Path& filter_file)
{
    abe::AdFilterManager ad_filter_manager;
    ad_filter_manager.LoadAdFilter(filter_file);
    ad_filter_manager.SnapshotAdFilter(filter_file);
    kbase::Path snapshot_file(filter_file);
    snapshot_file.ReplaceExtension(L".abx");
    ENSURE(CHECK, kbase::PathExists(snapshot_file)).Require();
    std::cout << "-> " << __FUNCTION__ << " passed\n";
}

int main()
{
    kbase::Path filter_path(LR"(src\test\easylistchina.txt)");
    abe::AdFilterManager ad_filter_manager;
    auto start = GetTickCount();
    ad_filter_manager.LoadAdFilter(filter_path);
    auto end = GetTickCount();
    std::cout << end - start;
    //abe::AdFilter ad_filter(filter_path);
    //TestAdFilterMatchAny(ad_filter);
    //TestAdFilterElementHide(ad_filter);
    //TestAdFilterSerialization(filter_path);
    _getch();
    return 0;
}