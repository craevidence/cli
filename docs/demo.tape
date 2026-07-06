# Hero demo for the CRA Evidence CLI README.
# Regenerate from the repo root with:  vhs docs/demo.tape
# Requires vhs, ttyd, ffmpeg, plus craevidence + grype + syft on PATH.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 620
Set Theme "GitHub Dark"
Set TypingSpeed 55ms
Set Padding 20
Set WindowBar Colorful

Hide
Type "export PS1='$ '" Enter
Type "WORK=$(mktemp -d); cp docs/demo-assets/sbom.cdx.json $WORK/; cd $WORK" Enter
Type "clear" Enter
Show

Sleep 800ms
# One hero command: a free local security check that gates CI on
# actively-exploited vulnerabilities.
Type "craevidence check --sbom sbom.cdx.json --fail-on known-exploited"
Sleep 800ms
Enter
Sleep 12s
Type 'echo "CI gate exit code: $?"'
Sleep 600ms
Enter
Sleep 3500ms
