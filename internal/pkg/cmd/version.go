package cmd

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/bep/simplecobra"
)

type versionCommand struct {
	name string

	commands []simplecobra.Commander
}

func (c *versionCommand) Name() string {
	return c.name
}

func (c *versionCommand) Init(cd *simplecobra.Commandeer) error {
	cmd := cd.CobraCommand
	cmd.Short = fmt.Sprintf("Show the version of %s", cd.Root.Command.Name())

	return nil
}

func (c *versionCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	return nil
}

func (c *versionCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Printf("%s Unknown\n", cd.Root.Command.Name())
	}
	fmt.Printf("%s %s\n", cd.Root.Command.Name(), info.Main.Version)

	return nil
}

func (c *versionCommand) Commands() []simplecobra.Commander {
	return c.commands
}
