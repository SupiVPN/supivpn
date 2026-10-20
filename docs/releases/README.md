# Release notes

`make tag VERSION=vX.Y.Z` embeds generated notes in a local signed annotated tag.
It selects the highest lower signed ancestor version and summarizes the exact
commit range. With no preceding tag, it summarizes the available history.

Subjects are escaped as text and linked to their full GitHub commit SHAs.
Keep commit and pull-request titles descriptive. At most 256 commits and
32 KiB of notes are accepted. A promotion at the same commit explicitly reports
that there are no source changes.

Review compatibility separately: commit subjects cannot establish configuration,
API or database compatibility. Publication uses the signed notes without
regenerating them and appends verified package and source information.

Historical notes are kept in [earlier releases](../history/). Creating a new tag
does not require a version-specific documentation commit.
See [release delivery](../RELEASES.md) and [earlier releases](../history/).
