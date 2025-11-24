// Step 2: Add MAC address retrieval
#include <hooks/hooks.h>
#include <dhcpsrv/lease.h>
#include <dhcp/hwaddr.h>
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
    std::cout << "DNS Hijack Hook v3: Loaded" << std::endl;
    return 0;
}

int unload() {
    std::cout << "DNS Hijack Hook v3: Unloaded" << std::endl;
    return 0;
}

int lease4_select(CalloutHandle& handle) {
    std::cout << "DNS Hijack Hook v3: lease4_select START" << std::endl;
    std::cout.flush();
    
    try {
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        if (lease) {
            std::cout << "DNS Hijack Hook v3: Got lease" << std::endl;
            std::cout.flush();
            
            std::string ip = lease->addr_.toText();
            std::cout << "DNS Hijack Hook v3: IP=" << ip << std::endl;
            std::cout.flush();
            
            // Try to get MAC address
            std::cout << "DNS Hijack Hook v3: Getting hwaddr..." << std::endl;
            std::cout.flush();
            
            HWAddrPtr hwaddr = lease->hwaddr_;
            
            std::cout << "DNS Hijack Hook v3: Got hwaddr pointer" << std::endl;
            std::cout.flush();
            
            if (hwaddr) {
                std::cout << "DNS Hijack Hook v3: hwaddr is valid" << std::endl;
                std::cout.flush();
                
                std::string mac = hwaddr->toText(false);
                std::cout << "DNS Hijack Hook v3: MAC=" << mac << std::endl;
                std::cout.flush();
            } else {
                std::cout << "DNS Hijack Hook v3: hwaddr is NULL" << std::endl;
                std::cout.flush();
            }
        }
        
    } catch (const std::exception& ex) {
        std::cout << "DNS Hijack Hook v3: ERROR: " << ex.what() << std::endl;
        std::cout.flush();
    }
    
    handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
    std::cout << "DNS Hijack Hook v3: lease4_select END" << std::endl;
    std::cout.flush();
    return 0;
}

int lease4_renew(CalloutHandle& handle) {
    std::cout << "DNS Hijack Hook v3: lease4_renew START" << std::endl;
    std::cout.flush();
    
    try {
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        if (lease) {
            std::cout << "DNS Hijack Hook v3: Got lease" << std::endl;
            std::cout.flush();
            
            std::string ip = lease->addr_.toText();
            std::cout << "DNS Hijack Hook v3: IP=" << ip << std::endl;
            std::cout.flush();
            
            // Try to get MAC address
            std::cout << "DNS Hijack Hook v3: Getting hwaddr..." << std::endl;
            std::cout.flush();
            
            HWAddrPtr hwaddr = lease->hwaddr_;
            
            std::cout << "DNS Hijack Hook v3: Got hwaddr pointer" << std::endl;
            std::cout.flush();
            
            if (hwaddr) {
                std::cout << "DNS Hijack Hook v3: hwaddr is valid" << std::endl;
                std::cout.flush();
                
                std::string mac = hwaddr->toText(false);
                std::cout << "DNS Hijack Hook v3: MAC=" << mac << std::endl;
                std::cout.flush();
            } else {
                std::cout << "DNS Hijack Hook v3: hwaddr is NULL" << std::endl;
                std::cout.flush();
            }
        }
        
    } catch (const std::exception& ex) {
        std::cout << "DNS Hijack Hook v3: ERROR: " << ex.what() << std::endl;
        std::cout.flush();
    }
    
    handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
    std::cout << "DNS Hijack Hook v3: lease4_renew END" << std::endl;
    std::cout.flush();
    return 0;
}

}
