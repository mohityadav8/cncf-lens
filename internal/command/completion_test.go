package command

import (
	"strings"
	"testing"
)

// The completion scripts hardcode the command list for speed. This test is what
// stops that list drifting away from the commands actually registered.
func TestCompletionListsEveryCommand(t *testing.T) {
	registered := []string{
		"diagnose", "trace", "watch", "audit",
		"cost", "doctor", "init", "completion",
	}
	for _, name := range registered {
		if !strings.Contains(commandList, name) {
			t.Errorf("commandList is missing %q — bash completion will not offer it", name)
		}
		if !strings.Contains(zshCompletion, name+":") {
			t.Errorf("zsh completion is missing %q", name)
		}
		if !strings.Contains(fishCompletion, "-a "+name+" ") {
			t.Errorf("fish completion is missing %q", name)
		}
	}
}

func TestCompletionScriptsAreNonEmpty(t *testing.T) {
	for name, script := range map[string]string{
		"bash": bashCompletion,
		"zsh":  zshCompletion,
		"fish": fishCompletion,
	} {
		if len(strings.TrimSpace(script)) < 100 {
			t.Errorf("%s completion script looks empty", name)
		}
	}
}

// A malformed script silently breaks the user's shell startup, so the shape of
// each is asserted rather than assumed.
func TestCompletionScriptShape(t *testing.T) {
	if !strings.Contains(bashCompletion, "complete -F _lens_completions lens") {
		t.Error("bash script does not register its completion function")
	}
	if !strings.HasPrefix(zshCompletion, "#compdef lens") {
		t.Error("zsh script must start with the #compdef directive")
	}
	if !strings.Contains(fishCompletion, "complete -c lens") {
		t.Error("fish script does not register completions for lens")
	}
}

func TestGlobalFlagsAreOffered(t *testing.T) {
	for _, flag := range []string{"--namespace", "--since", "--output", "--context"} {
		if !strings.Contains(globalFlagList, flag) {
			t.Errorf("globalFlagList is missing %s", flag)
		}
	}
}
