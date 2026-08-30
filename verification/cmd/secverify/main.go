package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	verify "github.com/secengcommons/verify"
	"github.com/secengcommons/verify/goverify"
)

const developmentVersion = "development"
const processOwner = "proctree@local-pre-release"

var exitProcess = os.Exit

func main() {
	runMain(os.Args, os.Stdout, os.Stderr, exitProcess, verify.DispatchProcessOwner)
}

func runMain(arguments []string, stdout, stderr io.Writer, exit func(int), dispatch func([]string) (bool, int)) {
	if handled, code := dispatch(arguments); handled {
		exit(code)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	exit(run(ctx, arguments, stdout, stderr))
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	return runWith(ctx, arguments, stdout, stderr, os.Getwd, repositoryPolicy)
}

func runWith(
	ctx context.Context,
	arguments []string,
	stdout, stderr io.Writer,
	currentDirectory func() (string, error),
	buildPolicy func() (goverify.Repository, error),
) int {
	return runWithOperations(ctx, arguments, stdout, stderr, currentDirectory, buildPolicy, goverify.RunMutations)
}

func runWithOperations(
	ctx context.Context,
	arguments []string,
	stdout, stderr io.Writer,
	currentDirectory func() (string, error),
	buildPolicy func() (goverify.Repository, error),
	runMutations func(context.Context, string, goverify.MutationCampaign, io.Writer) error,
) int {
	if len(arguments) == 0 || stdout == nil || stderr == nil {
		return verify.ExitInvocation
	}
	root, err := currentDirectory()
	if err != nil {
		return writeFailure(stderr, err)
	}
	identity := verify.CurrentIdentity(developmentVersion, processOwner)
	if code, handled := diagnosticRun(ctx, root, arguments, stdout, stderr, identity); handled {
		return code
	}
	policy, err := buildPolicy()
	if err != nil {
		return writeFailure(stderr, err)
	}
	if handled, specialErr := runSpecial(ctx, root, policy, arguments[1:], stdout, runMutations); handled {
		if specialErr != nil {
			return writeFailure(stderr, specialErr)
		}
		return verify.ExitPass
	}
	return goverify.RunRepositoryCLI(ctx, root, policy, identity, arguments[1:], stdout, stderr)
}

func runSpecial(
	ctx context.Context,
	root string,
	policy goverify.Repository,
	arguments []string,
	output io.Writer,
	runMutations func(context.Context, string, goverify.MutationCampaign, io.Writer) error,
) (bool, error) {
	if len(arguments) != 1 || arguments[0] != "__cvss-formula-mutations" {
		return false, nil
	}
	return true, runMutations(ctx, root, formulaMutations(policy.Go), output)
}

func diagnosticRun(
	ctx context.Context,
	root string,
	arguments []string,
	stdout, stderr io.Writer,
	identity verify.Identity,
) (int, bool) {
	if len(arguments) == 2 && arguments[1] != "help" && arguments[1] != "--help" && arguments[1] != "--version" {
		return 0, false
	}
	return verify.RunCLI(ctx, root, goverify.RepositoryPlanShape(repositoryShape()), identity, arguments[1:], stdout, stderr), true
}

func writeFailure(stderr io.Writer, err error) int {
	code := verify.ExitFail
	if errors.Is(err, context.Canceled) {
		code = verify.ExitCancelled
	} else if errors.Is(err, verify.ErrInvocation) || errors.Is(err, verify.ErrInvalidPlan) {
		code = verify.ExitInvocation
	} else if errors.Is(err, verify.ErrUnavailable) {
		code = verify.ExitUnavailable
	}
	if writeErr := writeAll(stderr, []byte("secverify: "+err.Error()+"\n")); writeErr != nil {
		return verify.ExitInvocation
	}
	return code
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if written < 0 || written > len(value) {
			return errors.New("writer returned an invalid count")
		}
		value = value[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
