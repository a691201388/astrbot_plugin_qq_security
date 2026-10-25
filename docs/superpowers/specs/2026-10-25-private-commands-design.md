# Private QQ command scope

The owner requested that command-related replies, including plugin commands, be
available only in the administrator private chat. Group commands are silent even
when sent by an administrator. Ordinary `/聊天内容` wake input and general code
explanations remain available. This extends the response-guidance work; it does
not authorize live installation or change the frozen persona experiment.

## Approach and scope

Prompt-only suppression cannot stop plugin handlers or argument-error replies.
Filtering only activated handlers is too late: AstrBot's waking stage can already
send help and permission errors. Add a reversible waking-stage preflight based
on the active registered CommandFilter, CommandGroupFilter and RegexFilter
metadata, before executing any filters or parsing parameters. Keep a late
activated-handler check and suppress sends for a blocked event.

The exception uses the actual OneBot private sender, an empty group ID, the
computer QQ whitelist and the effective AstrBot `admins_id`. It does not require
full Codex execution to be enabled, so command help remains usable during an
emergency stop. This is a builder choice; it grants no additional tool or command
permissions. Existing administrator command allowlists and lifecycle rules stay.

All registered plugin commands, aliases, command groups and regex command
handlers are covered, including help/status/reset, image/search and fish-social
commands. A leading slash alone is not a command: an unmatched wake utterance
continues to ordinary chat. Blocked commands cause no callback, usage message,
permission message or model fallback. QQ non-admin private chats also have no
command access. WebChat/manual administration keep existing behavior.

Natural-language requests for this bot's command list, plugin configuration,
permissions or real host actions receive a silence instruction and a suppressed
response marker. General programming tutorials and natural-language image/search
requests remain available. This semantic distinction is model guidance, not a
deterministic guarantee; the actual tool permissions remain enforced in code.

## Verification and limits

Exercise the real AstrBot waking stage with registered synthetic handlers,
including missing parameters and permission errors, aliases, command groups,
regex commands, administrator groups, untrusted nicknames and alternate wakes.
Verify no handler effects, no sends and no model fallthrough for blocked input;
verify ordinary wake input and authorized private command delivery remain usable.
Verify response-marker suppression, streaming and reversible wrapper lifecycle.
Run the existing suite, lint and format checks. No real QQ messages, credentials,
runtime config changes or deployment. Same-process hostile plugins using raw
transport APIs remain outside this plugin's isolation boundary.
