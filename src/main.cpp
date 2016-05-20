/*
 @ 0xCCCCCCCC
*/

#include <conio.h>

#include <iostream>

#include "adblock_engine/ad_filter.h"

int main()
{
    kbase::Path filter_path(LR"(C:\Projects\KAdBlockEngine\src\test\easylistchina.txt)");
    abe::AdFilter ad_filter(filter_path);
    auto& filter_info = ad_filter.GetFilterInfo();
    std::cout << filter_info.title << std::endl << filter_info.last_modified;
    _getch();
    return 0;
}