
```sh
sprites create mal-1
download and exec install-ida.sh

npm install -g @anthropic-ai/claude-code
npm install -g @mariozechner/pi-coding-agent
python -m uv tool update-shell
python -m uv tool install claude-code-transcripts
zsh # or restart shell

sprites-env checkpoints create  # v1

claude
  # do auth, then
  /plugin marketplace add https://github.com/williballenthin/aiwilli
  /plugin install ida@williballenthin

sprites-env checkpoints create  # v2

claude --dangerously-skip-permissions
  using your idalib analysis skill, download the following executable, triage it for disposition, indicators, capabilities, behaviors, and, if malware, methods to detect it on a
  network and host:
  https://github.com/mandiant/capa-testfiles/raw/refs/heads/master/0ce3bfa972ced61884ae7c1d77c7d4c45e17c7d767e669610cf2ef72b636b464.exe_
```

```sh
export OPENROUTER_API_KEY=sk-or-v1-...
gh auth login  # for sharing gists

# pi doesn't look in Claude plugin directories
# so copy the skills
cp -r ~/.claude/plugins/cache/williballenthin/ida/0.2.0/skills/analyze-with-ida-domain-api ~/.claude/skills

sprites-env checkpoints create  # v3

gh repo clone mandiant/capa-rules

sprites-env checkpoints create  # v4

# sprite doesn't seem to have the npm binary directory in its path
/.sprite/languages/node/nvm/versions/node/v22.20.0/bin/pi --model=google/gemini-3-flash-preview
```


---

Using your idalib analysis skill, download the following executable, triage it for disposition, indicators, capabilities, behaviors, and, if malware, methods to detect it on a network and host:

You can run capa like this (try the default, and --verbose modes), with the already existing rules:
  python -m uv run --python 3.12 --with flare-capa capa --rules capa-rules --backend ida sample.exe

https://github.com/mandiant/capa-testfiles/raw/refs/heads/master/0ce3bfa972ced61884ae7c1d77c7d4c45e17c7d767e669610cf2ef72b636b464.exe_

Use capa first. Then use IDA.

Run lots of little scripts, not a few big ones. One idea, one script.
Prefer to run Python snippets via something like `python -c "..."` rather than two step write/exec.

---

Weird, sprite python doesn't have bzip2 compiled in, so have to use a different python interpreter via uv.

Transcripts:
Gemini, pretty good: https://buildwithpi.ai/session/#96a8c214aeb81469ea9edbdd930af077
Some random model (Jamba Large), embarassing: https://buildwithpi.ai/session/#98158e18dba2d2cdd151fddc26e14699
GLM-4.7, pretty good: https://buildwithpi.ai/session/#79a96299a425951ef150ee8aacd3166c

TODO:
  - [ ] skill: recommend running `python -c ...` rather than writing out scripts
