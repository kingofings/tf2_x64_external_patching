This is a memory patch for linux tf2 that I have already made in sourcemod before.
However I'm just waiting for sourcemod to fully support 64 bit tf2.
Reason I made this was for fun and learning, as I have never messed with memory from an external Process
This will probably break very quickly and shouldn't be used.

# What this patch does

This Patch removes the distance limit from the Backscatters minicrit in CTFGameRules::ApplyOnDamageModifyRules() by patching a JBE instruction to JO
