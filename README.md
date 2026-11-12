# NanoNOS

A SONiC-style network switch stack in C++20 for Linux: a SAI-like hardware
abstraction over a software ASIC pipeline, an orchestration agent, BGP-4 and
LLDP, QoS, control-plane policing, TAP host interfaces and a leaf-spine fabric
test in network namespaces.

Documentation with architecture and measured results is in progress.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
sudo bash scripts/test_clos.sh   # Linux: 4 switches + 2 hosts in network namespaces
```
