# Proof of concept for [blacklanternsecurity's](https://github.com/blacklanternsecurity/red-run) Claude Code automated pentesting system

This is a writeup written by Claude Code using the GitHub repository written by blacklanternsecurity (all credit to them). It's a test of the ability on an already solved machine.

Check [nexus_claude_writeup.md](/nexus_claude_writeup.md)

**Some Notes:**

Much of the process was slowed down due to meticulously checking each command run by Claude. Total run was about 48mins. Speed could be drastically improved if `--dangerously-skip-permissions` is added. 

If you attempt to replicate the same box with `red-run` make sure to not let the agents or "teammates" get stuck on a CVE called `CVE-2021-3129`. Check the same for all the other boxes that this is applied to.

For improving efficiency - have Claude create a "Reflection" file for it to use as context for future machines. It improves token use efficiency and reduces general downtime spent waiting for teammates to succeed. 