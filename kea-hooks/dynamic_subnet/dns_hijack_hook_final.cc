// Final version: Full DNS hijacking hook
#include <hooks/hooks.h>
#include <dhcpsrv/lease.h>
#include <dhcp/hwaddr.h>
#include <dhcpsrv/host_mgr.h>
#include <dhcpsrv/host.h>
#include <dhcp/pkt4.h>
#include <dhcpsrv/subnet.h>
#include <iostream>
#include <cstdlib>

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
    std::cout << "DNS Hijack Hook FINAL: Loaded" << std::endl;
    return 0;
}

int unload() {
    std::cout << "DNS Hijack Hook FINAL: Unloaded" << std::endl;
    return 0;
}

// Call script without capturing output - fire and forget
void call_script(const std::string& action, const std::string& ip) {
    std::cout << "DNS Hijack Hook FINAL: Calling script " << action << " for " << ip << std::endl;
    std::cout.flush();
    
    std::string cmd = "/scripts/dns-hijack.sh " + action + " " + ip + " >/dev/null 2>&1 &";
    system(cmd.c_str());
}

int lease4_select(CalloutHandle& handle) {
    try {
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        Pkt4Ptr query4;
        handle.getArgument("query4", query4);
        
        if (!lease || !query4) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        HWAddrPtr hwaddr = query4->getHWAddr();
        if (!hwaddr) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::string ip = lease->addr_.toText();
        std::string mac = hwaddr->toText();
        
        std::cout << "DNS Hijack Hook FINAL: lease4_select - MAC=" << mac << " IP=" << ip << std::endl;
        std::cout.flush();
        
        // Check for reservation
        ConstHostPtr host = HostMgr::instance().get4Any(SUBNET_ID_GLOBAL, Host::IDENT_HWADDR,
                                                         &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
        
        if (!host) {
            ConstSubnet4Ptr subnet;
            handle.getArgument("subnet4", subnet);
            if (subnet) {
                host = HostMgr::instance().get4Any(subnet->getID(), Host::IDENT_HWADDR,
                                                   &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
            }
        }
        
        if (host) {
            std::cout << "DNS Hijack Hook FINAL: Device REGISTERED - unhijack" << std::endl;
            std::cout.flush();
            call_script("unhijack", ip);
        } else {
            std::cout << "DNS Hijack Hook FINAL: Device UNREGISTERED - hijack" << std::endl;
            std::cout.flush();
            call_script("hijack", ip);
        }
        
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 0;
        
    } catch (const std::exception& ex) {
        std::cout << "DNS Hijack Hook FINAL ERROR in lease4_select: " << ex.what() << std::endl;
        std::cout.flush();
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 1;
    }
}

int lease4_renew(CalloutHandle& handle) {
    try {
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        if (!lease) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        HWAddrPtr hwaddr = lease->hwaddr_;
        if (!hwaddr) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::string ip = lease->addr_.toText();
        std::string mac = hwaddr->toText(false);
        
        std::cout << "DNS Hijack Hook FINAL: lease4_renew - MAC=" << mac << " IP=" << ip << std::endl;
        std::cout.flush();
        
        // Check for reservation
        ConstHostPtr host = HostMgr::instance().get4Any(SUBNET_ID_GLOBAL, Host::IDENT_HWADDR,
                                                         &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
        
        if (!host) {
            ConstSubnet4Ptr subnet;
            handle.getArgument("subnet4", subnet);
            if (subnet) {
                host = HostMgr::instance().get4Any(subnet->getID(), Host::IDENT_HWADDR,
                                                   &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
            }
        }
        
        if (host) {
            std::cout << "DNS Hijack Hook FINAL: Device REGISTERED - unhijack" << std::endl;
            std::cout.flush();
            call_script("unhijack", ip);
        } else {
            std::cout << "DNS Hijack Hook FINAL: Device UNREGISTERED - hijack" << std::endl;
            std::cout.flush();
            call_script("hijack", ip);
        }
        
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 0;
        
    } catch (const std::exception& ex) {
        std::cout << "DNS Hijack Hook FINAL ERROR in lease4_renew: " << ex.what() << std::endl;
        std::cout.flush();
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 1;
    }
}

}
