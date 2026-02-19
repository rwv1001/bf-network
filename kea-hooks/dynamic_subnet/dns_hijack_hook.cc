// #include <config.h>  // Not needed for basic hooks
#include <hooks/hooks.h>
#include <dhcp/pkt4.h>
#include <dhcp/hwaddr.h>
#include <dhcpsrv/subnet.h>
#include <dhcpsrv/host_mgr.h>
#include <dhcpsrv/host.h>
#include <dhcpsrv/client_class_def.h>
#include <dhcpsrv/lease.h>
#include <asiolink/io_address.h>
#include <cc/data.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <string>
#include <map>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

using namespace isc::hooks;
using namespace isc::dhcp;
using namespace isc::asiolink;

extern "C" {

int version() {
    return 30002;  // Kea 3.0.2 - hardcoded since we compile with 2.6.3 headers
}

// Declare multi-threading compatibility
int multi_threading_compatible() {
    return 1;
}

int load(LibraryHandle& handle) {
    std::cout << "DNS Hijack Hook: Loaded successfully" << std::endl;
    return 0;
}

int unload() {
    std::cout << "DNS Hijack Hook: Unloaded" << std::endl;
    return 0;
}

// Helper function to call DNS hijacking script
void manage_dns_hijack(const std::string& action, const std::string& ip_address) {
    std::cout << "DNS Hijack Hook: [DEBUG] manage_dns_hijack ENTRY (action=" 
              << action << ", ip=" << ip_address << ")" << std::endl;
    std::cout.flush();
    
    std::stringstream cmd;
    
    std::cout << "DNS Hijack Hook: [DEBUG] Building command" << std::endl;
    std::cout.flush();
    
    // Run inline (quick iptables updates) to avoid fork failures
    cmd << "/scripts/dns-hijack.sh " << action << " " << ip_address << " >/dev/null 2>&1";
    
    std::cout << "DNS Hijack Hook: [DEBUG] Command: " << cmd.str() << std::endl;
    std::cout.flush();
    
    std::cout << "DNS Hijack Hook: [DEBUG] Calling system()" << std::endl;
    std::cout.flush();
    
    int status = system(cmd.str().c_str());
    
    std::cout << "DNS Hijack Hook: [DEBUG] system() returned: " << status << std::endl;
    std::cout.flush();
    
    if (status == -1) {
        std::cerr << "DNS Hijack Hook WARNING: Script launch failed errno="
                  << errno << " (" << std::strerror(errno) << ")" << std::endl;
        std::cerr.flush();
    } else if (status != 0) {
        std::cerr << "DNS Hijack Hook WARNING: Script exit status " << status << std::endl;
        std::cerr.flush();
    }
    
    std::cout << "DNS Hijack Hook: [DEBUG] manage_dns_hijack EXIT" << std::endl;
    std::cout.flush();
}

// Helper function to call DNS hijacking script without an IP argument
void manage_dns_hijack_pools(const std::string& action) {
    std::cout << "DNS Hijack Hook: [DEBUG] manage_dns_hijack_pools ENTRY (action="
              << action << ")" << std::endl;
    std::cout.flush();

    std::stringstream cmd;
    cmd << "/scripts/dns-hijack.sh " << action << " >/dev/null 2>&1";

    std::cout << "DNS Hijack Hook: [DEBUG] Pools Command: " << cmd.str() << std::endl;
    std::cout.flush();

    int status = system(cmd.str().c_str());
    if (status == -1) {
        std::cerr << "DNS Hijack Hook WARNING: Pools script launch failed errno="
                  << errno << " (" << std::strerror(errno) << ")" << std::endl;
        std::cerr.flush();
    } else if (status != 0) {
        std::cerr << "DNS Hijack Hook WARNING: Pools script exit status " << status << std::endl;
        std::cerr.flush();
    }
}

bool is_blocked_pool_ip(const std::string& ip_address) {
    std::size_t last_dot = ip_address.rfind('.');
    if (last_dot == std::string::npos || last_dot + 1 >= ip_address.size()) {
        return false;
    }

    int last_octet = -1;
    try {
        last_octet = std::stoi(ip_address.substr(last_dot + 1));
    } catch (...) {
        return false;
    }

    return (last_octet >= 214 && last_octet <= 254);
}

// Helper function to call HP5130 ACL script
void manage_acl(const std::string& action, const std::string& ip_address) {
    std::cout << "DNS Hijack Hook: [DEBUG] manage_acl ENTRY (action="
              << action << ", ip=" << ip_address << ")" << std::endl;
    std::cout.flush();

    std::stringstream cmd;
    cmd << "/scripts/hp5130-acl.sh " << action << " " << ip_address << " >/dev/null 2>&1 &";

    std::cout << "DNS Hijack Hook: [DEBUG] ACL Command: " << cmd.str() << std::endl;
    std::cout.flush();

    int status = system(cmd.str().c_str());
    std::cout << "DNS Hijack Hook: [DEBUG] ACL system() returned: " << status << std::endl;
    std::cout.flush();
    if (status == -1) {
        std::cerr << "DNS Hijack Hook WARNING: ACL script launch failed errno="
                  << errno << " (" << std::strerror(errno) << ")" << std::endl;
        std::cerr.flush();
    } else if (status != 0) {
        std::cerr << "DNS Hijack Hook WARNING: ACL script exit status " << status << std::endl;
        std::cerr.flush();
    }
}

// Helper function to track unregistered leases in DB
void manage_unregistered_lease(const std::string& action,
                               const std::string& mac_address,
                               const std::string& ip_address,
                               int lease_seconds) {
    std::stringstream cmd;
    if (action == "cleanup") {
        cmd << "/scripts/unregistered-lease.sh cleanup >/dev/null 2>&1";
    } else if (action == "upsert") {
        cmd << "/scripts/unregistered-lease.sh upsert " << mac_address
            << " " << ip_address << " " << lease_seconds << " >/dev/null 2>&1";
    } else if (action == "remove" || action == "expire") {
        cmd << "/scripts/unregistered-lease.sh remove " << mac_address
            << " " << ip_address << " >/dev/null 2>&1";
    } else {
        return;
    }

    int status = system(cmd.str().c_str());
    if (status == -1) {
        std::cerr << "DNS Hijack Hook WARNING: unregistered-lease script launch failed errno="
                  << errno << " (" << std::strerror(errno) << ")" << std::endl;
        std::cerr.flush();
    } else if (status != 0) {
        std::cerr << "DNS Hijack Hook WARNING: unregistered-lease script exit status "
                  << status << std::endl;
        std::cerr.flush();
    }
}

// Helper: extract "blocked-ip" from reservation user-context if present
std::string get_blocked_ip_from_reservation(const ConstHostPtr& host) {
    if (!host) {
        return "";
    }

    try {
        isc::data::ConstElementPtr ctx = host->getContext();
        if (!ctx || (ctx->getType() != isc::data::Element::map)) {
            return "";
        }

        isc::data::ConstElementPtr blocked_ip = ctx->get("blocked-ip");
        if (!blocked_ip) {
            return "";
        }

        if (blocked_ip->getType() == isc::data::Element::string) {
            return blocked_ip->stringValue();
        }
    } catch (...) {
        return "";
    }

    return "";
}

bool is_blocked_host(const ConstHostPtr& host) {
    if (!host) {
        return false;
    }

    // Prefer client-classes if present
    try {
        const ClientClasses& classes4 = host->getClientClasses4();
        if (classes4.contains("BLOCKED")) {
            return true;
        }
    } catch (...) {
        // Ignore and fall back to user-context
    }

    try {
        isc::data::ConstElementPtr ctx = host->getContext();
        if (!ctx || (ctx->getType() != isc::data::Element::map)) {
            return false;
        }

        isc::data::ConstElementPtr blocked = ctx->get("blocked");
        if (!blocked) {
            return false;
        }

        if (blocked->getType() == isc::data::Element::boolean) {
            return blocked->boolValue();
        }
    } catch (...) {
        return false;
    }

    return false;
}

// Helper: fire-and-forget switch port lookup.
// Uses a double-fork so Kea never needs to waitpid() for the grandchild,
// and SIGCHLD is never touched - avoiding interference with system() calls
// elsewhere in the hook.
// Gated by SWITCH_PORT_LOOKUP_ENABLED=1 env var (default off).
void spawn_port_lookup(const std::string& mac_colon) {
    const char* enabled = std::getenv("SWITCH_PORT_LOOKUP_ENABLED");
    if (!enabled || std::string(enabled) != "1") {
        return;
    }

    std::cout << "DNS Hijack Hook: Spawning port lookup for MAC " << mac_colon << std::endl;
    std::cout.flush();

    // Double-fork: first child exits immediately so Kea can waitpid() it
    // right away with no delay; grandchild runs the script detached.
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "DNS Hijack Hook: port lookup fork failed: " << std::strerror(errno) << std::endl;
        return;
    }
    if (pid == 0) {
        // --- First child ---
        pid_t pid2 = fork();
        if (pid2 != 0) {
            // First child exits immediately (pid2 > 0) or on error (pid2 < 0).
            _exit(0);
        }
        // --- Grandchild: detach and exec the script ---
        setsid();
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        // Close any other inherited fds
        for (int fd = 3; fd < 256; fd++) close(fd);

        static char mac_arg[64];
        std::strncpy(mac_arg, mac_colon.c_str(), sizeof(mac_arg) - 1);
        mac_arg[sizeof(mac_arg) - 1] = '\0';
        char* const args[] = {
            const_cast<char*>("/scripts/hp5130-port-lookup.sh"),
            mac_arg,
            nullptr
        };
        execv("/scripts/hp5130-port-lookup.sh", args);
        _exit(127);
    }
    // Parent: wait for first child (exits instantly), then return.
    // This reaps the first child immediately - no zombies, no SIGCHLD games.
    int status;
    waitpid(pid, &status, 0);
}

int lease4_select(CalloutHandle& handle) {
    try {
        // Get the lease that was selected
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        // Get the query packet
        Pkt4Ptr query4;
        handle.getArgument("query4", query4);
        
        if (!lease || !query4) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        // Get hardware address
        HWAddrPtr hwaddr = query4->getHWAddr();
        if (!hwaddr) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }

        // Async switch port lookup (non-blocking; result written to mac_port_cache)
        spawn_port_lookup(hwaddr->toText(false));
        
        // Get the allocated IP address
        std::string ip_address = lease->addr_.toText();
        std::string mac_address = hwaddr->toText();
        int lease_seconds = static_cast<int>(lease->valid_lft_);
        
        std::cout << "DNS Hijack Hook: Lease allocated - MAC: " << mac_address 
                  << " IP: " << ip_address << std::endl;
        
        // Cleanup expired unregistered leases on every allocation
        manage_unregistered_lease("cleanup", "", "", 0);

        // Check if device has a reservation (is registered)
        ConstHostPtr host;
        
        // Check global reservations
        host = HostMgr::instance().get4Any(SUBNET_ID_GLOBAL, Host::IDENT_HWADDR,
                                          &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
        
        // Check subnet-specific reservations if not found globally
        if (!host) {
            ConstSubnet4Ptr subnet;
            handle.getArgument("subnet4", subnet);
            if (subnet) {
                host = HostMgr::instance().get4Any(subnet->getID(), Host::IDENT_HWADDR,
                                                   &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
            }
        }
        
        if (host) {
            bool blocked = is_blocked_host(host);
            std::string blocked_ip = get_blocked_ip_from_reservation(host);
            isc::data::ConstElementPtr ctx = host->getContext();

            if (ctx) {
                std::cout << "DNS Hijack Hook: [DEBUG] user-context=" << ctx->str() << std::endl;
            }
            try {
                const ClientClasses& classes4 = host->getClientClasses4();
                std::cout << "DNS Hijack Hook: [DEBUG] client-classes=" << classes4.toText() << std::endl;
            } catch (...) {
                std::cout << "DNS Hijack Hook: [DEBUG] client-classes unavailable" << std::endl;
            }

            if (blocked) {
                std::cout << "DNS Hijack Hook: Device " << mac_address
                          << " is BLOCKED - enabling DNS hijack" << std::endl;
                if (is_blocked_pool_ip(ip_address)) {
                    std::cout << "DNS Hijack Hook: [DEBUG] Ensuring blocked-pool DNS hijack ranges" << std::endl;
                    manage_dns_hijack_pools("hijack-blocked-pools");
                }
                manage_dns_hijack("hijack", ip_address);
            } else {
                std::cout << "DNS Hijack Hook: Device " << mac_address
                          << " is REGISTERED - removing DNS hijack" << std::endl;
                manage_dns_hijack("unhijack", ip_address);
                manage_acl("unblock", ip_address);
            }

            manage_unregistered_lease("remove", mac_address, ip_address, 0);

            if (!blocked_ip.empty() && blocked_ip != ip_address) {
                std::cout << "DNS Hijack Hook: [DEBUG] Removing ACL for blocked IP: "
                          << blocked_ip << std::endl;
                manage_acl("unblock", blocked_ip);

                std::cout << "DNS Hijack Hook: [DEBUG] Removing per-IP DNS hijack for: "
                          << blocked_ip << std::endl;
                manage_dns_hijack("unhijack", blocked_ip);
            }
        } else {
            std::cout << "DNS Hijack Hook: Device " << mac_address 
                      << " is UNREGISTERED - enabling DNS hijack" << std::endl;
            manage_dns_hijack("hijack", ip_address);
            manage_acl("block", ip_address);
            manage_unregistered_lease("upsert", mac_address, ip_address, lease_seconds);
        }
        
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 0;
        
    } catch (const std::exception& ex) {
        std::cout << "DNS Hijack Hook ERROR: " << ex.what() << std::endl;
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 1;
    }
}

// Called when a lease is being renewed (RENEW/REBIND/INIT-REBOOT)
int lease4_renew(CalloutHandle& handle) {
    std::cout << "DNS Hijack Hook: [DEBUG] lease4_renew ENTRY" << std::endl;
    std::cout.flush();
    
    try {
        std::cout << "DNS Hijack Hook: [DEBUG] Getting lease4" << std::endl;
        std::cout.flush();
        
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        std::cout << "DNS Hijack Hook: [DEBUG] Got lease4, checking if NULL" << std::endl;
        std::cout.flush();
        
        if (!lease) {
            std::cout << "DNS Hijack Hook: [DEBUG] lease4 is NULL, returning" << std::endl;
            std::cout.flush();
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::cout << "DNS Hijack Hook: [DEBUG] Getting hwaddr from lease" << std::endl;
        std::cout.flush();
        
        // Get hardware address from lease
        HWAddrPtr hwaddr = lease->hwaddr_;
        
        std::cout << "DNS Hijack Hook: [DEBUG] Got hwaddr, checking if NULL" << std::endl;
        std::cout.flush();
        
        if (!hwaddr) {
            std::cout << "DNS Hijack Hook: [DEBUG] hwaddr is NULL, returning" << std::endl;
            std::cout.flush();
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }

        // Async switch port lookup (non-blocking; result written to mac_port_cache)
        spawn_port_lookup(hwaddr->toText(false));
        
        std::cout << "DNS Hijack Hook: [DEBUG] Converting IP to text" << std::endl;
        std::cout.flush();
        
        std::string ip_address = lease->addr_.toText();
        int lease_seconds = static_cast<int>(lease->valid_lft_);
        
        std::cout << "DNS Hijack Hook: [DEBUG] IP: " << ip_address << std::endl;
        std::cout.flush();
        
        std::cout << "DNS Hijack Hook: [DEBUG] Converting MAC to text" << std::endl;
        std::cout.flush();
        
        std::string mac_address = hwaddr->toText(false);
        
        std::cout << "DNS Hijack Hook: [DEBUG] MAC: " << mac_address << std::endl;
        std::cout.flush();
        
        std::cout << "DNS Hijack Hook: Lease renewal - MAC: " << mac_address 
                  << " IP: " << ip_address << std::endl;
        std::cout.flush();
        
        std::cout << "DNS Hijack Hook: [DEBUG] Checking for reservation" << std::endl;
        std::cout.flush();
        
        // Cleanup expired unregistered leases on every renewal
        manage_unregistered_lease("cleanup", "", "", 0);

        // Check if device has a reservation (is registered)
        ConstHostPtr host;
        
        std::cout << "DNS Hijack Hook: [DEBUG] Checking global reservations" << std::endl;
        std::cout.flush();
        
        // Check global reservations
        host = HostMgr::instance().get4Any(SUBNET_ID_GLOBAL, Host::IDENT_HWADDR,
                                          &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
        
        std::cout << "DNS Hijack Hook: [DEBUG] Global check done, host=" 
                  << (host ? "FOUND" : "NULL") << std::endl;
        std::cout.flush();
        
        // Check subnet-specific reservations if not found globally
        if (!host) {
            std::cout << "DNS Hijack Hook: [DEBUG] Checking subnet reservations" << std::endl;
            std::cout.flush();
            
            ConstSubnet4Ptr subnet;
            handle.getArgument("subnet4", subnet);
            
            std::cout << "DNS Hijack Hook: [DEBUG] Got subnet4" << std::endl;
            std::cout.flush();
            
            if (subnet) {
                std::cout << "DNS Hijack Hook: [DEBUG] Subnet valid, querying HostMgr" << std::endl;
                std::cout.flush();
                
                host = HostMgr::instance().get4Any(subnet->getID(), Host::IDENT_HWADDR,
                                                   &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
                
                std::cout << "DNS Hijack Hook: [DEBUG] Subnet check done, host=" 
                          << (host ? "FOUND" : "NULL") << std::endl;
                std::cout.flush();
            }
        }
        
        std::cout << "DNS Hijack Hook: [DEBUG] Reservation check complete" << std::endl;
        std::cout.flush();
        
        if (host) {
            bool blocked = is_blocked_host(host);
            std::string blocked_ip = get_blocked_ip_from_reservation(host);
            isc::data::ConstElementPtr ctx = host->getContext();

            if (ctx) {
                std::cout << "DNS Hijack Hook: [DEBUG] user-context=" << ctx->str() << std::endl;
                std::cout.flush();
            }
            try {
                const ClientClasses& classes4 = host->getClientClasses4();
                std::cout << "DNS Hijack Hook: [DEBUG] client-classes=" << classes4.toText() << std::endl;
                std::cout.flush();
            } catch (...) {
                std::cout << "DNS Hijack Hook: [DEBUG] client-classes unavailable" << std::endl;
                std::cout.flush();
            }

            if (blocked) {
                std::cout << "DNS Hijack Hook: Device " << mac_address
                          << " is BLOCKED - enabling DNS hijack" << std::endl;
                std::cout.flush();

                if (is_blocked_pool_ip(ip_address)) {
                    std::cout << "DNS Hijack Hook: [DEBUG] Ensuring blocked-pool DNS hijack ranges" << std::endl;
                    std::cout.flush();
                    manage_dns_hijack_pools("hijack-blocked-pools");
                }

                manage_dns_hijack("hijack", ip_address);
            } else {
                std::cout << "DNS Hijack Hook: Device " << mac_address
                          << " is REGISTERED - removing DNS hijack" << std::endl;
                std::cout.flush();

                manage_dns_hijack("unhijack", ip_address);
                manage_acl("unblock", ip_address);
            }

            manage_unregistered_lease("remove", mac_address, ip_address, 0);

            if (!blocked_ip.empty() && blocked_ip != ip_address) {
                std::cout << "DNS Hijack Hook: [DEBUG] Removing ACL for blocked IP: "
                          << blocked_ip << std::endl;
                std::cout.flush();
                manage_acl("unblock", blocked_ip);

                std::cout << "DNS Hijack Hook: [DEBUG] Removing per-IP DNS hijack for: "
                          << blocked_ip << std::endl;
                std::cout.flush();
                manage_dns_hijack("unhijack", blocked_ip);
            }
        } else {
            std::cout << "DNS Hijack Hook: Device " << mac_address 
                      << " is UNREGISTERED - enabling DNS hijack" << std::endl;
            std::cout.flush();
            
            std::cout << "DNS Hijack Hook: [DEBUG] Calling manage_dns_hijack(hijack)" << std::endl;
            std::cout.flush();
            
            manage_dns_hijack("hijack", ip_address);
            manage_acl("block", ip_address);
            manage_unregistered_lease("upsert", mac_address, ip_address, lease_seconds);
            
            std::cout << "DNS Hijack Hook: [DEBUG] manage_dns_hijack(hijack) returned" << std::endl;
            std::cout.flush();
        }
        
        std::cout << "DNS Hijack Hook: [DEBUG] Setting NEXT_STEP_CONTINUE" << std::endl;
        std::cout.flush();
        
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        
        std::cout << "DNS Hijack Hook: [DEBUG] lease4_renew EXIT (success)" << std::endl;
        std::cout.flush();
        return 0;
        
    } catch (const std::exception& ex) {
        std::cout << "DNS Hijack Hook ERROR in lease4_renew: " << ex.what() << std::endl;
        std::cout.flush();
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 1;
    }
}

// Called when a lease expires (cleanup ACL for released IP)
int lease4_expire(CalloutHandle& handle) {
    try {
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        if (!lease) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }

        std::string ip_address = lease->addr_.toText();
        std::string mac_address;
        HWAddrPtr hwaddr = lease->hwaddr_;
        if (hwaddr) {
            mac_address = hwaddr->toText(false);
        }
        std::cout << "DNS Hijack Hook: Lease expired - removing ACL for IP: " << ip_address << std::endl;
        std::cout.flush();

        manage_acl("unblock", ip_address);
        manage_dns_hijack("unhijack", ip_address);
        if (!mac_address.empty()) {
            manage_unregistered_lease("expire", mac_address, ip_address, 0);
        }

        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 0;

    } catch (const std::exception& ex) {
        std::cout << "DNS Hijack Hook ERROR in lease4_expire: " << ex.what() << std::endl;
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 1;
    }
}

}