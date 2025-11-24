// Step 3: Add HostMgr reservation check
#include <hooks/hooks.h>
#include <dhcpsrv/lease.h>
#include <dhcp/hwaddr.h>
#include <dhcpsrv/host_mgr.h>
#include <dhcpsrv/host.h>
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
    std::cout << "DNS Hijack Hook v4: Loaded" << std::endl;
    return 0;
}

int unload() {
    std::cout << "DNS Hijack Hook v4: Unloaded" << std::endl;
    return 0;
}

int lease4_renew(CalloutHandle& handle) {
    std::cout << "DNS Hijack Hook v4: lease4_renew START" << std::endl;
    std::cout.flush();
    
    try {
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        if (!lease) {
            std::cout << "DNS Hijack Hook v4: No lease" << std::endl;
            std::cout.flush();
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::string ip = lease->addr_.toText();
        std::cout << "DNS Hijack Hook v4: IP=" << ip << std::endl;
        std::cout.flush();
        
        HWAddrPtr hwaddr = lease->hwaddr_;
        if (!hwaddr) {
            std::cout << "DNS Hijack Hook v4: No hwaddr" << std::endl;
            std::cout.flush();
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::string mac = hwaddr->toText(false);
        std::cout << "DNS Hijack Hook v4: MAC=" << mac << std::endl;
        std::cout.flush();
        
        // Now try HostMgr - this is likely where it crashes
        std::cout << "DNS Hijack Hook v4: Getting HostMgr instance..." << std::endl;
        std::cout.flush();
        
        HostMgr& host_mgr = HostMgr::instance();
        
        std::cout << "DNS Hijack Hook v4: Got HostMgr instance" << std::endl;
        std::cout.flush();
        
        std::cout << "DNS Hijack Hook v4: Checking for reservation..." << std::endl;
        std::cout.flush();
        
        ConstHostPtr host = host_mgr.get4Any(SUBNET_ID_GLOBAL, Host::IDENT_HWADDR,
                                              &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
        
        std::cout << "DNS Hijack Hook v4: Reservation check done, host=" 
                  << (host ? "FOUND" : "NULL") << std::endl;
        std::cout.flush();
        
    } catch (const std::exception& ex) {
        std::cout << "DNS Hijack Hook v4: ERROR: " << ex.what() << std::endl;
        std::cout.flush();
    }
    
    handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
    std::cout << "DNS Hijack Hook v4: lease4_renew END" << std::endl;
    std::cout.flush();
    return 0;
}

int lease4_select(CalloutHandle& handle) {
    // Keep it simple for now, just continue
    handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
    return 0;
}

}
