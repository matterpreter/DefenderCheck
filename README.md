# DefenderCheck
Quick tool to help make evasion work a little bit easier.

Takes a binary as input and splits it until it pinpoints that exact byte that Microsoft Defender will flag on, and then prints those offending bytes to the screen. This can be helpful when trying to identify the specific bad pieces of code in your tool/payload.

![](/demo.gif)

**Note:** Defender must be enabled on your system, but the realtime protection and automatic sample submission features should be disabled.
