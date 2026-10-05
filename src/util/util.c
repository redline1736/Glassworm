#include "../global.h"
#include "util.h"


void delete_file(const char *file) {
    remove(file);
}

int line_count(const char *file) {
    FILE *fp = fopen(file, "r");
    if (!fp) return 0;
    int count = 0, c;
    while ((c = getc(fp)) != EOF)
        if (c == '\n') count++;
    fclose(fp);
    return count;
}

int find_string_in_file(const char *file, const char *string) {
    FILE *fp = fopen(file, "r");
    if (!fp) return 0;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (contains(line, string)) {
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found;
}
bool contains(const char *haystack, const char *needle) {
    return strstr(haystack, needle) != NULL;
}