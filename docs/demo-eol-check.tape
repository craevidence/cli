# Feature demo: eol-check. Regenerate with:  vhs docs/demo-eol-check.tape
Output docs/demo-eol-check.gif
Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 360
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
Type "craevidence eol-check --sbom sbom.cdx.json"
Sleep 800ms
Enter
Sleep 4500ms
