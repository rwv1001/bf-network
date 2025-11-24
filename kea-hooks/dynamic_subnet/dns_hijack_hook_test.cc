// Test: lease4_select with query4 access
#include <hooks/hooks.h>
#include <dhcpsrv/lease.h>
#include <dhcp/hwaddr.h>
#include <dhcp/pkt4.h>
#include <iostream>

using namespace isc::hooks;
using namespace isc::dhcp;

extern "C" {

int version() {
    return 30002;
}

int multi_threading_compatible() {
    return 1;
}

int load(LibraryHandle& handle) {
    std::cout << "DNS Hijack Hook TEST: Loaded" << std::endl;
    return 0;
}

int unload() {
    std::cout << "DNS Hijack Hook TEST: Unloaded" << std::endl;
    return 0;
}

int lease4_select(CalloutHandle& handle) {
    std::cout << "DNS Hijack Hook TEST: lease4_select ENTRY" << std::endl;
    std::cout.flush();
    
    try {
        std::cout << "DNS Hijack Hook TEST: Getting lease4..." << std::endl;
        std::cout.flush();
        
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        std::cout << "DNS Hijack Hook TEST: Got lease4" << std::endl;
        std::cout.flush();
        
        std::cout << "DNS Hijack Hook TEST: Getting query4..." << std::endl;
        std::cout.flush();
        
        Pkt4Ptr query4;
        handle.getArgument("query4", query4);
        
        std::cout << "DNS Hijack Hook TEST: Got query4" << std::endl;
        std::cout.flush();
        
        if (!lease || !query4) {
            std::cout << "DNS Hijack Hook TEST: lease or query4 is NULL" << std::endl;
            std::cout.flush();
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::cout << "DNS Hijack Hook TEST: Getting HWAddr from query4..." << std::endl;
        std::cout.flush();
        
        HWAddrPtr hwaddr = query4->getHWAddr();
        
        std::cout << "DNS Hijack Hook TEST: Got HWAddr from query4" << std::endl;
        std::cout.flush();
        
        if (hwaddr) {
            std::cout << "DNS Hijack Hook TEST: HWAddr valid" << std::endl;
            std::cout.flush();
        }
        
    } catch (const std::exception& ex) {
        std::cout << "DNS Hijack Hook TEST: ERROR: " << ex.what() << std::endl;
        std::cout.flush();
    }
    
    handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
    std::cout << "DNS Hijack Hook TEST: lease4_select EXIT" << std::endl;
    std::cout.flush();
    return 0;
}

int lease4_renew(CalloutHandle& handle) {
    // Simple passthrough
    handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
    return 0;
}

}
