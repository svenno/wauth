// Improved logging functionality

#include <stdio.h>
#include <time.h>
#include <string.h>

#define ENABLE_TIMESTAMPS 1
#define ENABLE_IP_LOGGING 1

void log_message(const char *level, const char *message, const char *remote_ip) {
    char log_buffer[256];
    time_t now;
    struct tm *tm_info;

    if (ENABLE_TIMESTAMPS) {
        time(&now);
        tm_info = localtime(&now);
        strftime(log_buffer, sizeof(log_buffer), "[%Y-%m-%d %H:%M:%S] ", tm_info);
    } else {
        log_buffer[0] = '\0'; // No timestamp
    }

    strcat(log_buffer, level);
    strcat(log_buffer, ": ");
    strcat(log_buffer, message);

    if (ENABLE_IP_LOGGING && remote_ip != NULL) {
        strcat(log_buffer, " (IP=");
        strcat(log_buffer, remote_ip);
        strcat(log_buffer, ")");
    }

    printf("%s\n", log_buffer);
}

int main() {
    log_message("INFO", "User logged in", "192.168.1.1");  // Example log
    return 0;
}