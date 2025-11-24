// Minimal hook - no Kea API calls, just logging
#include <hooks/hooks.h>
#include <iostream>

using namespace isc::hooks;

extern "C" {

int version() {
    return 30002;  // Kea 3.0.2
}

int multi_threading_compatible() {
    return 1;
}

int load(LibraryHandle& handle) {
    std::cout << "MINIMAL Hook: Loaded successfully" << std::endl;
    return 0;
}

int unload() {
    std::cout << "MINIMAL Hook: Unloaded" << std::endl;
    return 0;
}

int lease4_select(CalloutHandle& handle) {
    std::cout << "MINIMAL Hook: lease4_select called" << std::endl;
    std::cout.flush();
    handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
    return 0;
}

int lease4_renew(CalloutHandle& handle) {
    std::cout << "MINIMAL Hook: lease4_renew called" << std::endl;
    std::cout.flush();
    handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
    return 0;
}

}
