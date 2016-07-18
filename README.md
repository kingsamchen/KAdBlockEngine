
KAdBlockEngine
===

Yet another engine which is compatible with adblock plus rules.

### Usages

**Requirements**

- Visual Studio 2015 (Visual Studio 2013 doesn't support some features like `constexpr` and `auto`-deduced parameter in lambda etc.)

**Procedures**

1. Clone the repository and submodules in a folder of your own project

   `git clone --recursive https://github.com/kingsamchen/KAdBlockEngine.git`

2. Open the library at `libs/KBase/kbase.sln` and then build the `kbase` project

3. Include the engine source files.

Note: the repository provides a very limited `main.cpp` file for usage/test illustrations.