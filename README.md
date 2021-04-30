# DefenderCheck
Quick tool to help make evasion work a little bit easier.

> **Warning:** As of the 1.337.157.0 Defender signature update, [DefenderCheck is classified as VirTool:MSIL/BytzChk.C!MTB](https://twitter.com/matterpreter/status/1387858265686544393?s=20). As a workaround while I work to get around this, please disable Real-time Protection in Defender before compiling DefenderCheck.  

Takes a binary as input and splits it until it pinpoints that exact byte that Microsoft Defender will flag on, and then prints those offending bytes to the screen. This can be helpful when trying to identify the specific bad pieces of code in your tool/payload.

![](/demo.gif)

**Note:** Defender must be enabled on your system, but the realtime protection and automatic sample submission features should be disabled.
