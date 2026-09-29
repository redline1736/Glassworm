#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "graphql/graphql.h"
#include "sock/sock.h"

int run_graphql_scanning(char *path, char *url) {
    // Placeholder for the actual scanning logic
    printf("Scanning GraphQL files in path: %s\n", path);
    if (path != NULL){
        int result = graphql_scanning(path, true, NULL);
        return result;
    }else{
        int result = graphql_scanning(NULL, false, url);
        return result;       
    }
}
static void print_usage(const char *prog) {
    printf("Usage: %s <domain> <output_dir> <mode> [flags]\n", prog);
    printf("  mode: --gobuster  analyze gobuster results \n");
    printf("        --url");
    printf("Examples:\n");
    printf("  %s example.com output --url https://example.com/graqhql-api \n", prog);
    printf("  %s example.com output --gobuster ~/glassworm/results/ --tor\n", prog);
}
void banner(){
    printf("\033[1;32m");  /* bold green (optional) */
    printf("  ____  _ \n");
    printf(" / ___|| |  __ _  ___  ___ __      __  ___   _ __  _ __ ___  \n");
    printf("| |  _ | | / _` |/ __|/ __|\\ \\ /\\ / / / _ \\ | '__|| '_ ` _ \\ \n");
    printf("| |_| || || (_| |\\__ \\\\__ \\ \\ V  V / | (_) || |   | | | | | |\n");
    printf(" \\____||_| \\__,_||___/|___/  \\_/\\_/   \\___/ |_|   |_| |_| |_|\n");
    printf("\033[0m");      /* reset color */
    return 0;
}
int main(int argc, char *argv[]){
    banner();
    if (argc < 2 || strcmp(argv[2], "-h") == 0 || strcmp(argv[2], "-help") == 0){
        print_usage(argv[1]);
    }


}