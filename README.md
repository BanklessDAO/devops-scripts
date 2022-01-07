BanklessDAO DevOps Scripts
==========================
This repository contains various scripts used by BanklessDAO's [DevOps team](https://discord.gg/DyN6FN5QGM).  
These scripts are for various tasks the team performs such as user audits.

Scripts in repo
---------------
The following scripts are in the repo:

1. [github_audit.py](python/github_audit.py) - A simple GitHub organization auditing script for auditing repo settings
   1. TODO: Auditing of user access to repos will need to be added soon. 

pre-commit
----------
This repo uses Yelp's [pre-commit](https://pre-commit.com/) to manage some pre-commit hooks automatically.  
In order to use the hooks, make sure you have `pre-commit` in your `$PATH`.  
Once in your path you should run `pre-commit install` in order to configure it. If you push commits that fail pre-commit, your PR will
not pass tests and will not get merged.
