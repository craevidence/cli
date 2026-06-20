# Feature demo: offline CRA risk-catalog scaffold. Regenerate with:  vhs docs/demo-scaffold.tape
Output docs/demo-scaffold.gif
Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 240
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
Type "craevidence compliance-as-code template --type risk-catalog --offline --product example-service --sbom sbom.cdx.json --output risk-catalog.yaml"
Sleep 800ms
Enter
Sleep 4s
