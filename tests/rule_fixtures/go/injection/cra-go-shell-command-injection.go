package injection

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/exec"
)

func badEnvIntoShell() error {
	// ruleid: cra-go-shell-command-injection
	return exec.Command("sh", "-c", os.Getenv("USER_CMD")).Run()
}

func badEnvIntoBashViaVariable() error {
	command := os.Getenv("USER_CMD")
	// ruleid: cra-go-shell-command-injection
	return exec.Command("/bin/bash", "-c", command).Run()
}

func badRequestQueryIntoShell(r *http.Request) error {
	dir := r.URL.Query().Get("dir")
	// ruleid: cra-go-shell-command-injection
	return exec.Command("sh", "-c", "ls "+dir).Run()
}

func badFormValueIntoShell(r *http.Request) error {
	// ruleid: cra-go-shell-command-injection
	return exec.Command("zsh", "-c", r.FormValue("cmd")).Run()
}

func badHeaderIntoWindowsShell(r *http.Request) error {
	// ruleid: cra-go-shell-command-injection
	return exec.Command("cmd.exe", "/C", r.Header.Get("X-Command")).Run()
}

func badFlagIntoShellWithContext(ctx context.Context) error {
	target := flag.String("target", "", "target")
	// ruleid: cra-go-shell-command-injection
	return exec.CommandContext(ctx, "sh", "-c", "ping "+*target).Run()
}

func badEnvWrapperIntoShell() error {
	// ruleid: cra-go-shell-command-injection
	return exec.Command("/usr/bin/env", "sh", "-c", os.Getenv("USER_CMD")).Run()
}

func badBusyboxWrapperIntoShell() error {
	// ruleid: cra-go-shell-command-injection
	return exec.Command("busybox", "sh", "-c", os.Getenv("USER_CMD")).Run()
}

func badUppercaseWindowsShell() error {
	// ruleid: cra-go-shell-command-injection
	return exec.Command("CMD.EXE", "/C", os.Getenv("USER_CMD")).Run()
}

func badPowerShellCaseVariant() error {
	// ruleid: cra-go-shell-command-injection
	return exec.Command("powershell.exe", "-command", os.Getenv("USER_CMD")).Run()
}

// A value passed as a separate argument is never interpreted by a shell.
func okSeparateArgument(r *http.Request) error {
	// ok: cra-go-shell-command-injection
	return exec.Command("git", "checkout", r.FormValue("ref")).Run()
}

func okSeparateArgumentFromEnv() error {
	// ok: cra-go-shell-command-injection
	return exec.Command("ls", os.Getenv("USER_DIR")).Run()
}

// A fixed command string carries no process input.
func okFixedShellCommand() error {
	// ok: cra-go-shell-command-injection
	return exec.Command("sh", "-c", "uptime").Run()
}

// The program is not a shell, so -c is that program's own option.
func okNonShellDashC() error {
	// ok: cra-go-shell-command-injection
	return exec.Command("gcc", "-c", os.Getenv("SOURCE_FILE")).Run()
}

func okInternalValueIntoShell() error {
	// ok: cra-go-shell-command-injection
	return exec.Command("sh", "-c", buildMaintenanceCommand()).Run()
}

func buildMaintenanceCommand() string { return "systemctl restart app" }
