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
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <cstdio>
#include <cctype>
#include <mutex>

using namespace isc::hooks;
using namespace isc::dhcp;
using namespace isc::asiolink;

extern "C" {

int version() {
    return KEA_HOOKS_VERSION;  // Use the version from the Kea headers we compiled against
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

// Wrapper around system() that temporarily restores SIGCHLD to SIG_DFL.
// Kea sets SIGCHLD to SIG_IGN to auto-reap children; this causes system()'s
// internal waitpid() to fail with ECHILD even when the child ran successfully.
// Saving and restoring the handler makes the exit status reliable.
int run_script(const std::string& cmd) {
    struct sigaction sa_old, sa_new;
    sa_new.sa_handler = SIG_DFL;
    sigemptyset(&sa_new.sa_mask);
    sa_new.sa_flags = 0;
    sigaction(SIGCHLD, &sa_new, &sa_old);
    int status = system(cmd.c_str());
    sigaction(SIGCHLD, &sa_old, nullptr);
    return status;
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
    
    std::cout << "DNS Hijack Hook: [DEBUG] Calling run_script()" << std::endl;
    std::cout.flush();
    
    int status = run_script(cmd.str());
    
    std::cout << "DNS Hijack Hook: [DEBUG] run_script() returned: " << status << std::endl;
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

    int status = run_script(cmd.str());
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
    // Convert a dotted-quad string to a uint32_t for range comparisons.
    auto ip_to_u32 = [](const std::string& s) -> uint32_t {
        unsigned a = 0, b = 0, c = 0, d = 0;
        if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
        return (a << 24) | (b << 16) | (c << 8) | d;
    };

    // Cache blocked pool ranges on first call by reading the Kea config via Python.
    static std::mutex              s_mutex;
    static bool                    s_loaded = false;
    static std::vector<std::pair<uint32_t, uint32_t>> s_ranges;

    {
        std::lock_guard<std::mutex> lk(s_mutex);
        if (!s_loaded) {
            s_loaded = true;
            const char* cfg = std::getenv("KEA_CONFIG_PATH");
            if (!cfg || !*cfg) cfg = "/kea/config/dhcp4.json";
            std::string cmd =
                "python3 -c \""
                "import json\n"
                "with open('" + std::string(cfg) + "') as f:\n"
                "    data=json.load(f)\n"
                "for s in data.get('Dhcp4',{}).get('subnet4',[]):\n"
                "    for p in s.get('pools',[]):\n"
                "        if 'BLOCKED' in (p.get('client-classes') or []):\n"
                "            r=p['pool'].replace(' ','')\n"
                "            print(r)\n"
                "\" 2>/dev/null";
            FILE* pipe = popen(cmd.c_str(), "r");
            if (pipe) {
                char line[256];
                while (fgets(line, sizeof(line), pipe)) {
                    std::string range(line);
                    while (!range.empty() &&
                           (range.back() == '\n' || range.back() == '\r' || range.back() == ' '))
                        range.pop_back();
                    auto dash = range.find('-');
                    if (dash == std::string::npos) continue;
                    uint32_t start = ip_to_u32(range.substr(0, dash));
                    uint32_t end   = ip_to_u32(range.substr(dash + 1));
                    if (start && end && start <= end)
                        s_ranges.push_back({start, end});
                }
                pclose(pipe);
                std::cout << "DNS Hijack Hook: loaded " << s_ranges.size()
                          << " blocked-pool range(s) from " << cfg << std::endl;
            } else {
                std::cerr << "DNS Hijack Hook: WARNING is_blocked_pool_ip: "
                             "failed to load ranges from Kea config" << std::endl;
            }
        }
    }

    uint32_t ip = ip_to_u32(ip_address);
    if (ip == 0) return false;
    for (const auto& r : s_ranges) {
        if (ip >= r.first && ip <= r.second) return true;
    }
    return false;
}

// Helper: parse SWITCH_HOSTS (space-separated) env var.
std::vector<std::string> get_switch_hosts() {
    const char* env = std::getenv("SWITCH_HOSTS");
    std::vector<std::string> hosts;
    if (!env || !*env) return hosts;
    std::istringstream iss(env);
    std::string h;
    while (iss >> h) {
        if (!h.empty()) hosts.push_back(h);
    }
    return hosts;
}

// Helper: query isp_routers + vlan_mappings to find which HP5130 switch hosts
// the ISP router for the given device VLAN.  That switch is the internet choke
// point: blocking there prevents internet access regardless of which physical
// switch the device is currently connected to.
// vlan_id is an integer from the lease (no SQL injection risk).
std::string get_isp_router_switch_for_vlan(uint32_t vlan_id) {
    if (vlan_id == 0) return "";

    const char* db_host = std::getenv("DB_HOST");
    const char* db_port = std::getenv("DB_PORT");
    const char* db_name = std::getenv("DB_NAME");
    const char* db_user = std::getenv("DB_USER");
    const char* db_pass = std::getenv("DB_PASSWORD");
    if (!db_host || !db_name || !db_user || !db_pass) return "";

    setenv("PGPASSWORD", db_pass, 1);

    std::stringstream cmd;
    cmd << "psql -h " << db_host
        << " -p " << (db_port ? db_port : "5432")
        << " -U " << db_user
        << " -d " << db_name
        << " -t -A -q"
        << " -c \"SELECT ir.switch_host FROM isp_routers ir"
        << " JOIN vlan_mappings vm ON vm.isp_router_id = ir.id"
        << " WHERE vm.vlan_id = " << vlan_id
        << " AND ir.switch_host IS NOT NULL LIMIT 1\""
        << " 2>/dev/null";

    FILE* pipe = popen(cmd.str().c_str(), "r");
    if (!pipe) return "";
    char buf[64] = {};
    bool got = (fgets(buf, sizeof(buf) - 1, pipe) != nullptr);
    pclose(pipe);
    if (!got) return "";

    std::string result(buf);
    while (!result.empty() &&
           (result.back() == '\n' || result.back() == '\r' || result.back() == ' ')) {
        result.pop_back();
    }
    return result;
}

// Helper function to call HP5130 ACL script on the appropriate switch(es).
// For "block": targets only the ISP router's switch for the VLAN (the internet
//              choke point). Falls back to all switches if not configured.
// For "unblock": targets all switches to remove any stale deny rules.
void manage_acl(const std::string& action, const std::string& ip_address,
                uint32_t vlan_id = 0) {
    std::cout << "DNS Hijack Hook: [DEBUG] manage_acl ENTRY (action="
              << action << ", ip=" << ip_address
              << ", vlan=" << vlan_id << ")" << std::endl;
    std::cout.flush();

    std::vector<std::string> all_hosts = get_switch_hosts();
    if (all_hosts.empty()) {
        std::cerr << "DNS Hijack Hook WARNING: no SWITCH_HOSTS configured"
                  << std::endl;
        std::cerr.flush();
        return;
    }

    std::vector<std::string> targets;

    if (action == "block") {
        // Target only the ISP router's switch for this VLAN.
        std::string isp_sw = get_isp_router_switch_for_vlan(vlan_id);
        if (!isp_sw.empty()) {
            // Validate against the configured hosts list.
            for (const auto& h : all_hosts) {
                if (h == isp_sw) { targets.push_back(h); break; }
            }
        }
        if (targets.empty()) {
            std::cout << "DNS Hijack Hook: ACL block for " << ip_address
                      << " vlan=" << vlan_id
                      << " — ISP router switch not found, targeting all switches"
                      << std::endl;
            targets = all_hosts;
        } else {
            std::cout << "DNS Hijack Hook: ACL block for " << ip_address
                      << " targeting ISP router switch " << targets[0]
                      << " (vlan=" << vlan_id << ")" << std::endl;
        }
    } else {
        // Unblock: hit all switches to remove any stale deny rules.
        targets = all_hosts;
    }

    for (const auto& target : targets) {
        std::stringstream cmd;
        cmd << "SWITCH_HOSTS='" << target << "' ACL_QUEUE_DISABLE=1 /scripts/hp5130-acl.sh "
            << action << " " << ip_address << " >/dev/null 2>&1 &";

        std::cout << "DNS Hijack Hook: [DEBUG] ACL Command: " << cmd.str() << std::endl;
        std::cout.flush();

        int status = run_script(cmd.str());
        std::cout << "DNS Hijack Hook: [DEBUG] ACL run_script() returned: " << status << std::endl;
        std::cout.flush();
        if (status == -1) {
            std::cerr << "DNS Hijack Hook WARNING: ACL script launch failed for "
                      << target << " errno=" << errno
                      << " (" << std::strerror(errno) << ")" << std::endl;
            std::cerr.flush();
        }
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

    int status = run_script(cmd.str());
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

// Helper: query central for an unknown MAC via central_import.py.
// Returns one of: "registered", "blocked", "not_found", "disabled", "error".
// The call is synchronous but central_import.py uses a 3-second HTTP timeout,
// so the total wall time is bounded.  We validate the MAC before exec to
// prevent shell injection.
std::string query_central_for_mac(const std::string& mac_colon) {
    // Only allow hex digits and colons (aa:bb:cc:dd:ee:ff)
    if (mac_colon.size() > 17) return "error";
    for (unsigned char c : mac_colon) {
        if (!isxdigit(c) && c != ':') return "error";
    }

    // Build command — mac_colon already validated; single-quote the arg anyway
    std::string cmd = "python3 /scripts/central_import.py '" + mac_colon + "' 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "error";

    char buf[32] = {};
    bool got = (fgets(buf, sizeof(buf) - 1, pipe) != nullptr);
    pclose(pipe);
    if (!got) return "error";

    std::string result(buf);
    // Strip trailing whitespace / newline
    while (!result.empty() &&
           (result.back() == '\n' || result.back() == '\r' || result.back() == ' ')) {
        result.pop_back();
    }
    return result;
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

// Helper: fire-and-forget lease event notification for Table 6 + Table 7 writes.
// Calls /scripts/kea-lease-event.sh asynchronously via double-fork so Kea
// never blocks waiting for the DB write to complete.
void manage_lease_event(const std::string& action,
                        const std::string& mac_colon,
                        const std::string& ip_address,
                        uint32_t           vlan_id,
                        int                lease_seconds,
                        bool               from_blocked_pool,
                        bool               dns_hijacked) {
    static const char* script = "/scripts/kea-lease-event.sh";
    std::string vlan_str   = std::to_string(vlan_id);
    std::string secs_str   = std::to_string(lease_seconds);
    std::string pool_str   = from_blocked_pool ? "true" : "false";
    std::string hijack_str = dns_hijacked      ? "true" : "false";

    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "DNS Hijack Hook: manage_lease_event fork failed: "
                  << std::strerror(errno) << std::endl;
        return;
    }
    if (pid == 0) {
        // First child: fork again then exit immediately so Kea reaps it instantly.
        pid_t pid2 = fork();
        if (pid2 != 0) _exit(0);
        // Grandchild: detach from Kea and exec the script.
        setsid();
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        for (int fd = 3; fd < 256; fd++) close(fd);
        // Local arrays for execv args (stack-allocated in grandchild).
        char a_action[16], a_mac[32], a_ip[20], a_vlan[12],
             a_secs[12],   a_pool[8], a_hijack[8];
        std::strncpy(a_action,  action.c_str(),        sizeof(a_action)  - 1);
        std::strncpy(a_mac,     mac_colon.c_str(),     sizeof(a_mac)     - 1);
        std::strncpy(a_ip,      ip_address.c_str(),    sizeof(a_ip)      - 1);
        std::strncpy(a_vlan,    vlan_str.c_str(),      sizeof(a_vlan)    - 1);
        std::strncpy(a_secs,    secs_str.c_str(),      sizeof(a_secs)    - 1);
        std::strncpy(a_pool,    pool_str.c_str(),      sizeof(a_pool)    - 1);
        std::strncpy(a_hijack,  hijack_str.c_str(),    sizeof(a_hijack)  - 1);
        a_action[sizeof(a_action)-1] = a_mac[sizeof(a_mac)-1] = a_ip[sizeof(a_ip)-1] = '\0';
        a_vlan[sizeof(a_vlan)-1]     = a_secs[sizeof(a_secs)-1] = '\0';
        a_pool[sizeof(a_pool)-1]     = a_hijack[sizeof(a_hijack)-1] = '\0';
        char* const args[] = {
            const_cast<char*>(script),
            a_action, a_mac, a_ip, a_vlan, a_secs, a_pool, a_hijack,
            nullptr
        };
        execv(script, args);
        _exit(127);
    }
    // Reap first child immediately (it exits right away).
    int wstatus;
    waitpid(pid, &wstatus, 0);
}

// Synchronously query the portal DB to check whether a registered device's
// assigned_vlan matches the VLAN subnet being allocated.
// Returns true if there is a mismatch (device is on the wrong network segment
// and should have DNS hijack applied despite having a registered reservation).
// Only called for non-blocked registered devices; uses popen(psql).
// Latency: ~10-50 ms on a local PostgreSQL instance.
bool is_assigned_vlan_mismatch(const std::string& mac_colon, uint32_t lease_vlan_id) {
    // Input validation: MAC must contain only hex digits and colons.
    if (mac_colon.size() > 17) return false;
    for (char c : mac_colon) {
        if (!isxdigit(static_cast<unsigned char>(c)) && c != ':') return false;
    }

    const char* db_host = std::getenv("DB_HOST");
    const char* db_port = std::getenv("DB_PORT");
    const char* db_name = std::getenv("DB_NAME");
    const char* db_user = std::getenv("DB_USER");
    const char* db_pass = std::getenv("DB_PASSWORD");
    if (!db_host || !db_name || !db_user || !db_pass) return false;

    // Expose DB_PASSWORD as PGPASSWORD so psql authenticates without .pgpass.
    setenv("PGPASSWORD", db_pass, 1);

    std::stringstream cmd;
    cmd << "psql -h " << db_host
        << " -p " << (db_port ? db_port : "5432")
        << " -U " << db_user
        << " -d " << db_name
        << " -t -A -q"
        << " -c \"SELECT assigned_vlan FROM devices"
        << " WHERE mac_address='" << mac_colon << "'"
        << " AND assigned_vlan IS NOT NULL LIMIT 1\""
        << " 2>/dev/null";

    FILE* pipe = popen(cmd.str().c_str(), "r");
    if (!pipe) return false;

    char buf[32] = {};
    bool got_data = (fgets(buf, sizeof(buf) - 1, pipe) != nullptr);
    pclose(pipe);
    if (!got_data) return false;

    // Trim trailing whitespace / newline.
    std::string result(buf);
    while (!result.empty() &&
           (result.back() == '\n' || result.back() == '\r' || result.back() == ' ')) {
        result.pop_back();
    }
    if (result.empty()) return false;  // No assigned_vlan set — no mismatch.

    try {
        int assigned = std::stoi(result);
        if (assigned <= 0) return false;
        bool mismatch = (static_cast<uint32_t>(assigned) != lease_vlan_id);
        if (mismatch) {
            std::cout << "DNS Hijack Hook: VLAN mismatch for " << mac_colon
                      << " (assigned=" << assigned
                      << " lease_vlan=" << lease_vlan_id << ")" << std::endl;
        }
        return mismatch;
    } catch (...) {
        return false;
    }
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
        std::string ip_address  = lease->addr_.toText();
        std::string mac_address = hwaddr->toText();          // "hwtype=1 aa:bb:cc:dd:ee:ff"
        std::string mac_clean   = hwaddr->toText(false);     // "aa:bb:cc:dd:ee:ff" (for DB queries)
        int         lease_seconds      = static_cast<int>(lease->valid_lft_);
        bool        ip_is_blocked_pool = is_blocked_pool_ip(ip_address);

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

        bool do_hijack = false;  // track for lease event
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
                if (ip_is_blocked_pool) {
                    std::cout << "DNS Hijack Hook: [DEBUG] Ensuring blocked-pool DNS hijack ranges" << std::endl;
                    manage_dns_hijack_pools("hijack-blocked-pools");
                } else {
                    // Unusual: Kea should have put a BLOCKED device in the blocked pool.
                    std::cerr << "DNS Hijack Hook WARNING: blocked device " << mac_clean
                              << " received non-blocked-pool IP " << ip_address
                              << " (subnet_id=" << lease->subnet_id_ << ")" << std::endl;
                }
                manage_dns_hijack("hijack", ip_address);
                do_hijack = true;
            } else {
                // Registered (non-blocked) device.
                // Check assigned_vlan: if the device is on the wrong network segment,
                // restrict access even though it has a valid registration.
                if (is_assigned_vlan_mismatch(mac_clean, lease->subnet_id_)) {
                    std::cout << "DNS Hijack Hook: Device " << mac_clean
                              << " registered but on wrong VLAN (subnet "
                              << lease->subnet_id_ << ") - restricting access" << std::endl;
                    manage_dns_hijack("hijack", ip_address);
                    manage_acl("block", ip_address, lease->subnet_id_);
                    do_hijack = true;
                } else {
                    std::cout << "DNS Hijack Hook: Device " << mac_address
                              << " is REGISTERED - removing DNS hijack" << std::endl;
                    manage_dns_hijack("unhijack", ip_address);
                    manage_acl("unblock", ip_address, lease->subnet_id_);
                    do_hijack = false;
                }
            }

            manage_unregistered_lease("remove", mac_address, ip_address, 0);

            if (!blocked_ip.empty() && blocked_ip != ip_address) {
                std::cout << "DNS Hijack Hook: [DEBUG] Removing ACL for blocked IP: "
                          << blocked_ip << std::endl;
                manage_acl("unblock", blocked_ip, lease->subnet_id_);

                std::cout << "DNS Hijack Hook: [DEBUG] Removing per-IP DNS hijack for: "
                          << blocked_ip << std::endl;
                manage_dns_hijack("unhijack", blocked_ip);
            }
        } else {
            // No local reservation — query central before treating as unregistered.
            std::string central_status = query_central_for_mac(mac_clean);
            std::cout << "DNS Hijack Hook: Device " << mac_clean
                      << " not in local DB - central query returned: "
                      << central_status << std::endl;
            std::cout.flush();

            if (central_status == "registered" || central_status == "blocked") {
                // Device was imported from central and a Kea reservation was added.
                // Drop this offer so the client re-DISCOVERs and picks up the new
                // reservation (correct pool assignment).
                std::cout << "DNS Hijack Hook: Device " << mac_clean
                          << " imported from central (status=" << central_status
                          << ") - dropping offer for re-DISCOVER" << std::endl;
                std::cout.flush();
                manage_unregistered_lease("remove", mac_address, ip_address, 0);
                handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
                return 0;
            }

            // not_found / disabled / error → fail-open: treat as unregistered
            std::cout << "DNS Hijack Hook: Device " << mac_address
                      << " is UNREGISTERED - enabling DNS hijack" << std::endl;
            std::cout.flush();
            manage_dns_hijack("hijack", ip_address);
            // Blocked-pool IPs are already covered by blanket ACL range rules;
            // a redundant per-IP rule would survive lease expiry and litter the ACL.
            if (!ip_is_blocked_pool) {
                manage_acl("block", ip_address, lease->subnet_id_);
            }
            manage_unregistered_lease("upsert", mac_address, ip_address, lease_seconds);
            do_hijack = true;
        }

        // Table 6 + Table 7: record this new lease in the portal DB (async).
        manage_lease_event("new_lease", mac_clean, ip_address,
                           lease->subnet_id_, lease_seconds,
                           ip_is_blocked_pool, do_hijack);

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
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);

        if (!lease) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }

        // Get hardware address from lease
        HWAddrPtr hwaddr = lease->hwaddr_;
        if (!hwaddr) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }

        // Async switch port lookup (non-blocking; result written to mac_port_cache)
        spawn_port_lookup(hwaddr->toText(false));

        std::string ip_address        = lease->addr_.toText();
        std::string mac_address       = hwaddr->toText(false);  // clean colon format
        int         lease_seconds     = static_cast<int>(lease->valid_lft_);
        bool        ip_is_blocked_pool = is_blocked_pool_ip(ip_address);

        std::cout << "DNS Hijack Hook: Lease renewal - MAC: " << mac_address
                  << " IP: " << ip_address << std::endl;
        std::cout.flush();

        // Cleanup expired unregistered leases on every renewal
        manage_unregistered_lease("cleanup", "", "", 0);

        // Check if device has a reservation (registered or blocked)
        ConstHostPtr host;

        // Check global reservations first
        host = HostMgr::instance().get4Any(SUBNET_ID_GLOBAL, Host::IDENT_HWADDR,
                                          &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());

        // Fall back to subnet-specific reservations
        if (!host) {
            ConstSubnet4Ptr subnet;
            handle.getArgument("subnet4", subnet);
            if (subnet) {
                host = HostMgr::instance().get4Any(subnet->getID(), Host::IDENT_HWADDR,
                                                   &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
            }
        }

        std::cout << "DNS Hijack Hook: [DEBUG] Reservation check complete, host="
                  << (host ? "FOUND" : "NULL") << std::endl;
        std::cout.flush();

        bool do_hijack = false;
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

            // ── Pool mismatch detection: force DHCP NAK so the client re-discovers ──
            //
            // Case 1: Device is BLOCKED (BLOCKED Kea class) but is renewing a
            // non-blocked-pool IP — it was blocked after the lease was issued.
            // NAK the renewal so the client re-DHCPs and gets a blocked-pool IP.
            if (blocked && !ip_is_blocked_pool) {
                std::cout << "DNS Hijack Hook: Pool mismatch - BLOCKED device "
                          << mac_address << " renewing non-blocked IP "
                          << ip_address << " - sending NAK" << std::endl;
                std::cout.flush();
                // Apply hijack while the client waits for re-DHCP.
                manage_dns_hijack_pools("hijack-blocked-pools");
                manage_dns_hijack("hijack", ip_address);
                manage_acl("block", ip_address, lease->subnet_id_);
                manage_lease_event("expire", mac_address, ip_address,
                                   lease->subnet_id_, 0, false, true);
                handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
                return 0;
            }

            // Case 2: Device is now registered (no BLOCKED class) but is renewing a
            // stale blocked-pool IP from when it was previously blocked.
            // NAK so the client re-DHCPs and gets a regular-pool IP.
            if (!blocked && ip_is_blocked_pool) {
                std::cout << "DNS Hijack Hook: Pool mismatch - registered device "
                          << mac_address << " renewing blocked-pool IP "
                          << ip_address << " - sending NAK" << std::endl;
                std::cout.flush();
                // Remove the hijack so the fresh DHCPDISCOVER can succeed.
                manage_dns_hijack("unhijack", ip_address);
                manage_acl("unblock", ip_address, lease->subnet_id_);
                manage_lease_event("expire", mac_address, ip_address,
                                   lease->subnet_id_, 0, true, false);
                handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
                return 0;
            }

            if (blocked) {
                std::cout << "DNS Hijack Hook: Device " << mac_address
                          << " is BLOCKED - enabling DNS hijack" << std::endl;
                std::cout.flush();

                if (ip_is_blocked_pool) {
                    std::cout << "DNS Hijack Hook: [DEBUG] Ensuring blocked-pool DNS hijack ranges" << std::endl;
                    std::cout.flush();
                    manage_dns_hijack_pools("hijack-blocked-pools");
                }

                manage_dns_hijack("hijack", ip_address);
                do_hijack = true;
            } else {
                // Registered device — check whether it's on its assigned VLAN.
                if (is_assigned_vlan_mismatch(mac_address, lease->subnet_id_)) {
                    std::cout << "DNS Hijack Hook: Device " << mac_address
                              << " registered but on wrong VLAN (subnet "
                              << lease->subnet_id_ << ") - restricting access" << std::endl;
                    std::cout.flush();
                    manage_dns_hijack("hijack", ip_address);
                    manage_acl("block", ip_address, lease->subnet_id_);
                    do_hijack = true;
                } else {
                    std::cout << "DNS Hijack Hook: Device " << mac_address
                              << " is REGISTERED - removing DNS hijack" << std::endl;
                    std::cout.flush();
                    manage_dns_hijack("unhijack", ip_address);
                    manage_acl("unblock", ip_address, lease->subnet_id_);
                    do_hijack = false;
                }
            }

            manage_unregistered_lease("remove", mac_address, ip_address, 0);

            if (!blocked_ip.empty() && blocked_ip != ip_address) {
                std::cout << "DNS Hijack Hook: [DEBUG] Removing ACL for blocked IP: "
                          << blocked_ip << std::endl;
                std::cout.flush();
                manage_acl("unblock", blocked_ip, lease->subnet_id_);

                std::cout << "DNS Hijack Hook: [DEBUG] Removing per-IP DNS hijack for: "
                          << blocked_ip << std::endl;
                std::cout.flush();
                manage_dns_hijack("unhijack", blocked_ip);
            }
        } else {
            std::cout << "DNS Hijack Hook: Device " << mac_address
                      << " is UNREGISTERED - enabling DNS hijack" << std::endl;
            std::cout.flush();
            manage_dns_hijack("hijack", ip_address);
            if (!ip_is_blocked_pool) {
                manage_acl("block", ip_address, lease->subnet_id_);
            }
            manage_unregistered_lease("upsert", mac_address, ip_address, lease_seconds);
            do_hijack = true;
        }

        // Table 6 + Table 7: update the portal DB with renewal info (async).
        manage_lease_event("renew", mac_address, ip_address,
                           lease->subnet_id_, lease_seconds,
                           ip_is_blocked_pool, do_hijack);

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

        manage_acl("unblock", ip_address, lease->subnet_id_);
        manage_dns_hijack("unhijack", ip_address);
        if (!mac_address.empty()) {
            manage_unregistered_lease("expire", mac_address, ip_address, 0);
            // Table 7: mark lease as expired in portal DB (async).
            manage_lease_event("expire", mac_address, ip_address,
                               lease->subnet_id_, 0, false, false);
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