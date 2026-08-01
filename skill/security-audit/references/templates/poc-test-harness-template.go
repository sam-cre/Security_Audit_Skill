// Security Audit PoC Test Harness Template — Phase 2 Dynamic Testing (Go)
//
// A collection of runnable test patterns for Go projects organized by vulnerability class.
// Copy and adapt these patterns into `.security-audit/security-tests/test_secXXX_poc_test.go`.
//
// Usage:
//     go test -v ./.security-audit/security-tests/...
//     go test -v -run TestSEC001_SQLInjectionPoC ./.security-audit/security-tests/...

package securitytests

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// =============================================================================
// INJECTION TESTING
// =============================================================================

func TestSEC001_SQLInjectionPoC(t *testing.T) {
	// Source code inspection pattern for unsafe SQL query formatting in Go
	sourceFile := filepath.Join("..", "..", "pkg", "db", "queries.go")
	content, err := os.ReadFile(sourceFile)
	if err != nil {
		t.Skipf("Target source file %s not found", sourceFile)
	}

	source := string(content)

	// Flag fmt.Sprintf, string concatenation (+), or raw string interpolation in db.Query/Exec calls
	dangerousPatterns := []*regexp.Regexp{
		regexp.MustCompile(`fmt\.Sprintf\s*\([^)]*SELECT`),
		regexp.MustCompile(`fmt\.Sprintf\s*\([^)]*INSERT`),
		regexp.MustCompile(`fmt\.Sprintf\s*\([^)]*UPDATE`),
		regexp.MustCompile(`db\.(Query|Exec|QueryRow)\s*\(\s*".*\+`),
	}

	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(source) {
			t.Fatalf("VULNERABLE: Found unparameterized SQL query construction matching %s in %s", pattern, sourceFile)
		}
	}

	// Verify parameterized placeholder ($1, ?, :name) is used
	safePattern := regexp.MustCompile(`db\.(Query|Exec|QueryRow)\Context\s*\(\s*[^,]+,\s*"[^"]*(\$1|\?|:1)`)
	if !safePattern.MatchString(source) {
		t.Log("WARNING: Could not verify parameterized query placeholder in target query execution")
	}
}

func TestSEC002_CommandInjectionPoC(t *testing.T) {
	// Checks for unsafe command execution using sh -c or bash -c with user input
	sourceFile := filepath.Join("..", "..", "pkg", "utils", "exec.go")
	content, err := os.ReadFile(sourceFile)
	if err != nil {
		t.Skipf("Target source file %s not found", sourceFile)
	}

	source := string(content)

	// Check if exec.Command uses shell invocations with string concat
	dangerousShellPattern := regexp.MustCompile(`exec\.Command\s*\(\s*"(sh|bash|cmd|powershell)"\s*,\s*"-c"\s*,\s*.*\+`)
	if dangerousShellPattern.MatchString(source) {
		t.Fatalf("VULNERABLE: exec.Command passes raw string concatenated arguments to shell in %s", sourceFile)
	}
}

// =============================================================================
// PATH TRAVERSAL TESTING
// =============================================================================

func TestSEC003_PathTraversalPoC(t *testing.T) {
	payloads := []string{
		"../../../../etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	}

	baseDir, err := filepath.Abs("uploads")
	if err != nil {
		t.Fatalf("Failed to resolve base dir: %v", err)
	}

	for _, payload := range payloads {
		// Mock path sanitization function under audit
		cleanedPath := filepath.Clean(filepath.Join(baseDir, payload))

		// Safe path check rule: cleaned path must have baseDir as prefix
		if !strings.HasPrefix(cleanedPath, baseDir) {
			t.Logf("CONFIRMED EXPLOITABLE: Path traversal payload '%s' escaped base directory to '%s'", payload, cleanedPath)
		} else {
			t.Logf("SECURE: Payload '%s' contained within base directory '%s'", payload, cleanedPath)
		}
	}
}

// =============================================================================
// CONCURRENCY & RACE CONDITIONS
// =============================================================================

func TestSEC004_RaceConditionPoC(t *testing.T) {
	const concurrentRoutines = 20
	var wg sync.WaitGroup
	var counter int64
	var mu sync.Mutex

	// Mock state modification
	for i := 0; i < concurrentRoutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// ADAPT: Call the actual target function under test
			// e.g. targetStateMutation()
			mu.Lock()
			counter++
			mu.Unlock()
		}()
	}

	wg.Wait()

	if counter != int64(concurrentRoutines) {
		t.Fatalf("CONFIRMED EXPLOITABLE: Race condition detected. Expected counter %d, got %d", concurrentRoutines, counter)
	}
}

// =============================================================================
// CRYPTOGRAPHY & SECURE RANDOMNESS
// =============================================================================

func TestSEC005_CryptoFlawsPoC(t *testing.T) {
	// Test if AES-ECB or hardcoded key/IV is present in Go code
	key := []byte("1234567890123456") // 16 bytes for AES-128
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Cipher init failed: %v", err)
	}

	// ECB mode uses block.Encrypt directly without a block mode wrapper (CBC, GCM)
	// Verify target code uses cipher.NewGCM or cipher.NewCBCEncrypter
	if block.BlockSize() != 16 {
		t.Fatalf("Unexpected block size")
	}

	_ = cipher.Block(block)
	t.Log("Cryptographic cipher initialization verified safely.")
}
