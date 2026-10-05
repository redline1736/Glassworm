#include "cf.h"
#include "../global.h"
#include "../http/http.h"
#include "../util/util.h"

/* ============================================================
 * CSRF header name constants
 * ============================================================ */

/* --- Request-side headers that indicate a CSRF defense is being applied --- */
static const char *CSRF_REQUEST_HEADERS[] = {
    "X-CSRF-Token",
    "X-CSRFToken",
    "X-XSRF-Token",
    "X-CSRF",
    "X-Xsrf-Token",
    "Origin",
    "Referer",
    "Sec-Fetch-Site",
    "Sec-Fetch-Mode",
    NULL
};

/* --- Cookie names that indicate a double-submit CSRF defense --- */
static const char *CSRF_COOKIE_NAMES[] = {
    "XSRF-TOKEN",
    "csrftoken",
    "_csrf",
    "csrf_token",
    "CSRF-TOKEN",
    "csrftoken",
    "X-CSRF-TOKEN",
    NULL
};

/* --- Meta tag names that carry a CSRF token to JavaScript --- */
static const char *CSRF_META_NAMES[] = {
    "csrf-token",
    "csrf-param",
    "_csrf",
    "_csrf_header",
    "xsrf-token",
    NULL
};

/* --- Hidden input field names that carry a CSRF token in HTML forms --- */
static const char *CSRF_FORM_FIELDS[] = {
    "csrf_token",
    "_csrf",
    "_token",
    "authenticity_token",
    "__RequestVerificationToken",
    "csrfmiddlewaretoken",
    "X-CSRF-Token",
    NULL
};

/* --- Response-body phrases that indicate a token check rejected the request --- */
static const char *CSRF_ERROR_PHRASES[] = {
    "CSRF token missing",
    "CSRF verification failed",
    "CSRF token mismatch",
    "Invalid CSRF token",
    "Invalid authenticity token",
    "Can't verify CSRF token authenticity",
    "RequestVerificationToken",
    "Anti-forgery token",
    "anti-forgery",
    "_csrf token required",
    "csrf",
    "xsrf",
    "forgery",
    "verification failed",
    NULL
};

/* --- Headers that LOOK like CSRF defense but aren't --- */
static const char *CSRF_FALSE_POSITIVES[] = {
    "X-Requested-With",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "X-Frame-Options",
    "X-Content-Type-Options",
    NULL
};

void csrf_run(void) {
    // Implementation for initializing CSRF protection
}

int csrf_token_exists(char *target_url) {
    request r = {0};
    if (!http_send_post(&r, target_url, false, NULL, false, NULL)) {
        fprintf(stderr, "HTTP POST failed for %s\n", target_url);
    }
    for (int i = 0; CSRF_REQUEST_HEADERS[i] != NULL; i++) {
        if (find_string_in_file(r.filename, CSRF_REQUEST_HEADERS[i])) {
            return 1; // CSRF token header found
        }
    }

    return 0;
}
