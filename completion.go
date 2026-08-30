package main

import (
	"errors"
	"fmt"
)

// Static completions. Pastes have no index route and codes
// never reach the daemon in a readable form.
const (
	bashCompletion = `_tp() {
  local cmds="post get list del doctor completion version"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=($(compgen -W "$cmds" -- "${COMP_WORDS[1]}"))
    return
  fi
  case "${COMP_WORDS[1]}" in
    post) COMPREPLY=($(compgen -W "--label --ttl --max-gets --burn --code-style" -- "${COMP_WORDS[COMP_CWORD]}")) ;;
    get)  COMPREPLY=($(compgen -W "--host --timeout" -- "${COMP_WORDS[COMP_CWORD]}")) ;;
    del)  COMPREPLY=($(compgen -W "--all" -- "${COMP_WORDS[COMP_CWORD]}")) ;;
    completion) COMPREPLY=($(compgen -W "bash zsh fish" -- "${COMP_WORDS[COMP_CWORD]}")) ;;
  esac
}
complete -F _tp tp
`
	zshCompletion = `#compdef tp
_tp() {
  local -a cmds
  cmds=(
    'post:share stdin or a file'
    'get:fetch a paste'
    'list:show local pastes'
    'del:stop serving a paste'
    'doctor:explain why discovery is not working'
    'completion:print shell completions'
    'version:print the version'
  )
  if (( CURRENT == 2 )); then
    _describe 'command' cmds
    return
  fi
  case "$words[2]" in
    post) _arguments '--label=[label shown in tp list]' '--ttl=[time to live]' '--max-gets=[fetch cap]' '--burn[single fetch]' '--code-style=[words or digits]:style:(words digits)' '*:file:_files' ;;
    get)  _arguments '--host=[skip discovery]' '--timeout=[give up after]' ;;
    del)  _arguments '--all[drop every paste]' ;;
    doctor) _arguments '--fix[apply what this platform needs]' '--quiet[only print problems]' ;;
    completion) _values shell bash zsh fish ;;
  esac
}
_tp "$@"
`
	fishCompletion = `complete -c tp -f
complete -c tp -n __fish_use_subcommand -a post -d 'share stdin or a file'
complete -c tp -n __fish_use_subcommand -a get -d 'fetch a paste'
complete -c tp -n __fish_use_subcommand -a list -d 'show local pastes'
complete -c tp -n __fish_use_subcommand -a del -d 'stop serving a paste'
complete -c tp -n __fish_use_subcommand -a doctor -d 'explain why discovery is not working'
complete -c tp -n __fish_use_subcommand -a completion -d 'print shell completions'
complete -c tp -n __fish_use_subcommand -a version -d 'print the version'
complete -c tp -n '__fish_seen_subcommand_from post' -l label -l ttl -l max-gets -l code-style -r
complete -c tp -n '__fish_seen_subcommand_from post' -l burn
complete -c tp -n '__fish_seen_subcommand_from post' -F
complete -c tp -n '__fish_seen_subcommand_from get' -l host -l timeout -r
complete -c tp -n '__fish_seen_subcommand_from del' -l all
complete -c tp -n '__fish_seen_subcommand_from doctor' -l fix -l quiet
complete -c tp -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
`
)

func cmdCompletion(args []string) error {
	scripts := map[string]string{
		"bash": bashCompletion,
		"zsh":  zshCompletion,
		"fish": fishCompletion,
	}
	if len(args) != 1 {
		return errors.New("usage: tp completion <bash|zsh|fish>")
	}
	script, ok := scripts[args[0]]
	if !ok {
		return fmt.Errorf("unknown shell %q, try bash, zsh or fish", args[0])
	}
	fmt.Print(script)
	return nil
}
