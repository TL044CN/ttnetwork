# ttnetwork
custom network library for some lightweight networking.
## installation
1. run `cmake .` in the base directory to generate `Makefile`
2. run `make install` to create the `out` directory containing all necessary files.
3. copy the content of `out/include` into the directory where your projects
   includes live
4. copy the appropriate Lib into your linking directory or whatever...
  - libttnetwork.a: Static Library
  - libttnetwork_dbg.a: Static Library with debugging capability
  - libttnetwork.so: Dynamic Library
  - libttnetwork_dbg.so: Dynamic Library with debugging capability
