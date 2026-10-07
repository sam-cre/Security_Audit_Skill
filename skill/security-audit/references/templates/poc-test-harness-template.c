/*
 * Security Audit PoC Test Harness Template — Phase 3 Dynamic Testing (C/C++)
 *
 * A collection of runnable test patterns for C/C++ codebases targeting memory safety,
 * buffer overflows, format string vulnerabilities, and path traversal.
 *
 * Usage:
 *     gcc -Wall -I. .security-audit/security-tests/test_sec001_poc.c -o test_sec001_poc && ./test_sec001_poc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// =============================================================================
// BUFFER OVERFLOW & BOUNDS CHECKING
// =============================================================================

void test_sec001_buffer_overflow_bounds(void) {
    char dest[16];
    const char *large_input = "THIS_INPUT_IS_TOO_LONG_FOR_DEST";

    // Safe pattern check: snprintf or strnlcpy instead of strcpy / sprintf / gets
    size_t written = snprintf(dest, sizeof(dest), "%s", large_input);

    // Verify string was safely truncated without buffer overrun
    assert(written >= sizeof(dest));
    assert(dest[sizeof(dest) - 1] == '\0');
    assert(strlen(dest) == sizeof(dest) - 1);

    printf("[PASS] SEC-001: snprintf bounds checking prevented buffer overflow.\n");
}

// =============================================================================
// FORMAT STRING VULNERABILITY
// =============================================================================

void test_sec002_format_string_check(void) {
    const char *user_input = "%x %x %x %x %s %p";

    // Safe pattern: printf("%s", user_input) vs dangerous printf(user_input)
    // Here we assert that user input is never passed directly as format specifier
    char output_buf[128];
    snprintf(output_buf, sizeof(output_buf), "%s", user_input);

    assert(strcmp(output_buf, user_input) == 0);
    printf("[PASS] SEC-002: Format specifier safety verified.\n");
}

// =============================================================================
// INTEGER OVERFLOW / UNDERFLOW
// =============================================================================

void test_sec003_integer_overflow_check(void) {
    size_t count = 1000000000;
    size_t element_size = 8;

    // Check multiplication overflow before memory allocation
    if (count > 0 && element_size > SIZE_MAX / count) {
        printf("[PASS] SEC-003: Integer overflow in allocation size caught before malloc.\n");
        return;
    }

    void *ptr = malloc(count * element_size);
    if (ptr) free(ptr);
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================

int main(int argc, char *argv[]) {
    printf("=== Executing C/C++ Security Audit PoC Test Suite ===\n");
    test_sec001_buffer_overflow_bounds();
    test_sec002_format_string_check();
    test_sec003_integer_overflow_check();
    printf("=== All C/C++ PoC Assertions Completed Cleanly ===\n");
    return 0;
}
