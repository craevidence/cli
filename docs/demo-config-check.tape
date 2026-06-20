# Feature demo: config-check. Regenerate with:  vhs docs/demo-config-check.tape
Output docs/demo-config-check.gif
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
Type "WORK=$(mktemp -d); cp docs/demo-assets/Dockerfile $WORK/; cd $WORK" Enter
Type "clear" Enter
Show
Sleep 800ms
Type "craevidence config-check ."
Sleep 800ms
Enter
Sleep 4500ms
