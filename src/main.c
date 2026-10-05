
#include "global.h"
#include "graphql/gq.h"
#include "sock/sock.h"
#include "util/util.h"
#include "http/http.h"

static void print_usage(const char *prog) {
    printf("Usage: %s <mode> [value]\n", prog);
    printf("  modes:\n");
    printf("    --url <target_url>        scan a single GraphQL endpoint (output written to ./)\n");
    printf("    --gobuster <gobuster_dir>  analyze gobuster.txt already in <gobuster_dir>\n");
    printf("Examples:\n");
    printf("  %s --url https://example.com/graphql\n", prog);
    printf("  %s --gobuster ~/gobuster/\n", prog);
}

void banner(void){
    printf("\033[1;32m");
    printf("  ____  _ \n");
    printf(" / ___|| |  __ _  ___  ___ __      __  ___   _ __  _ __ ___  \n");
    printf("| |  _ | | / _` |/ __|/ __|\\ \\ /\\ / / / _ \\ | '__|| '_ ` _ \\ \n");
    printf("| |_| || || (_| |\\__ \\\\__ \\ \\ V  V / | (_) || |   | | | | | |\n");
    printf(" \\____||_| \\__,_||___/|___/  \\_/\\_/   \\___/ |_|   |_| |_| |_|\n");
    printf("\033[0m");
}

int main(int argc, char *argv[]){
    banner();

    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    curl_http_init();

    char *mode = argv[1];

    if (strcmp(mode, "-h") == 0 || strcmp(mode, "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    if (strcmp(mode, "--url") == 0) {
        char *target_url = argv[2];
        return graphql_scanning(".", false, target_url);
    }
    else if (strcmp(mode, "--gobuster") == 0) {
        char *gobuster_dir = argv[2];
        return graphql_scanning(gobuster_dir, true, NULL);
    }

    fprintf(stderr, "Error: unknown mode '%s'\n\n", mode);
    print_usage(argv[0]);
    curl_http_cleanup();
    
    return 1;
}