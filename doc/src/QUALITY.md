# Data quality, prevention & limitations

What the reports can prove, how to protect yourself, and where the
tool's coverage ends.

## Data quality

One's email can be spoofed in commits: an address read in a commit
proves nothing about who owns the mailbox. Cross-check the confidence
grades of the `email` reports and the per-author summary of the
correlation report (`--json`) before drawing conclusions. To open a
cited piece of evidence, run `git2mail email <address>`: its report
carries the repository and the commit `sha` (the long identifier after
`/commit/` in a GitHub URL) that proves the attribution: build the
commit URL as `https://github.com/<owner>/<repo>/commit/<sha>`. The
`scan` and `search` reports carry repositories and counts but no commit
sha, so the reverse lookup is the evidence step.

A note on pull requests: when a contributor's pull request was
squash-merged through GitHub's web interface, the squashed commit's
**author** email is the contributor's private
`id+username@users.noreply.github.com` alias (GitHub stamps its own
web-flow identity, `noreply@github.com`, as the **committer**). The
`scan` and `search` subcommands filter out the
`users.noreply.github.com` domain, so the squashed commit contributes
nothing to them: a prolific pull-request contributor can therefore stay
invisible to the `scan` and `search` subcommands; the `user` subcommand
recovers their identities through the commit history instead.

## Prevention

Harden your account privacy by enabling these
[settings](https://github.com/settings/emails):

- Keep my email addresses private
- Block command line pushes that expose my email

These settings protect only future commits: an address you committed
with before stays in the repository's history and clones. Run
`git2mail user <your-username>` on yourself for the full picture of
what this tool recovers about you (history, guessed addresses,
secondary accounts), and rewrite old history (for example with
`git filter-repo`) if you need it gone.

## Limitations

This project is limited to GitHub repositories. The `user` investigation
reads both the commit **author** and **committer** emails when they
differ (the committer is a real second channel, rarely different but
sometimes the only one that leaks); the repository and keyword scans
read the commit **author** email.

Per-subcommand coverage deltas live in the page of the feature they
constrain: the default-branch-only commit walk and the noreply-history
preconditions in [User investigation](USER.md), the candidate-search
visibility limits of the reverse lookup in
[Reverse email lookup](EMAIL.md), and the search ceilings in
[Scanning: scan & search](SCANNING.md).
