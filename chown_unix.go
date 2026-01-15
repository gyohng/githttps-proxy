//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// matchOwnership sets the ownership of targetPath to match referencePath.
// Only works when running as root (uid 0). Returns nil if not root or on success.
func matchOwnership(targetPath, referencePath string) error {
	// only attempt chown when running as root
	if os.Getuid() != 0 {
		return nil
	}

	info, err := os.Stat(referencePath)
	if err != nil {
		return fmt.Errorf("stat reference path: %w", err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not get syscall.Stat_t from file info")
	}

	uid := int(stat.Uid)
	gid := int(stat.Gid)

	if err := os.Chown(targetPath, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", targetPath, uid, gid, err)
	}

	return nil
}
