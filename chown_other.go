//go:build !unix

package main

// matchOwnership is a no-op on non-Unix systems.
func matchOwnership(targetPath, referencePath string) error {
	return nil
}
