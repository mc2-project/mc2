# Contributing to MC<sup>2</sup>

## Reporting bugs and asking questions

You can ask questions, bring up issues, or garner feedback through the following channels:

1. [Slack](https://join.slack.com/t/mc2-project/shared_invite/zt-rt3kxyy8-GS4KA0A351Ysv~GKwy8NEQ)
2. [GitHub Issues](https://github.com/mc2-project/mc2/issues)
3. Email: send an email to mc2-dev@googlegroups.com

## To contribute a patch

1. Break your work into small, single-purpose patches if possible. It's much
   harder to merge in a large change with a lot of disjoint features.
2. Submit the patch as a GitHub pull request against the master branch.
3. Make sure that your code passes the automated tests.
4. Make sure that your code passes the linter. Run `pip3 install pre-commit; pre-commit install` to create a git hook that will run the linter before you push your changes.
