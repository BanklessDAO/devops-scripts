#!/usr/bin/env python3
"""Check GitHub repos in a GitHub Org for basic security compliance
"""
#
# Python Script:: github_audit.py
#
# Linter:: pylint
# Environment: Local Poetry
#
# Copyright 2022, BanklessDAO, All Rights Reserved.
#
# Maintainers:
# - Matthew Ahrenstein: @ahrenstein
#
# See LICENSE
#

import argparse
import csv
import logging
import sys
from github import Github
from github import GithubException


# Static variables
MIN_CODE_OWNERS = 1 # The minimum amount of CODEOWNERS we prefer on a project


# Get a list of repositories in the GitHub org
def get_org_repos(github_pat: str, github_org: str) -> list:
    """Get a list of repositories that exist in a GitHub organization

    Args:
        github_pat: A GitHub personal access token
        github_org: The short name of a GitHub organization (the "username")

    Returns:
        org_repos: A python list containing the org repos
    """
    # Instantiate org_repos variable for return
    org_repos = []
    # Instantiate GitHub access
    gh_session = Github(github_pat)
    gh_user = gh_session.get_user()
    # Loop through repos the user has access to and add repos from the org to the list
    logging.info("Getting a list of repos from the %s organization", github_org)
    for repo in gh_user.get_repos():
        if github_org in repo.full_name:
            logging.info("Adding %s to the list", repo.full_name)
            org_repos.append(repo.full_name)
    return org_repos


def repo_check(github_pat: str, github_repos: list, strict_mode: bool) -> None:
    """Check a GitHub repo for basic or strict compliance settings

    Args:
        github_pat: A GitHub personal access token
        github_repos: A list of GitHub repositories (full name)
        strict_mode: If true, then have very strict security requirements

    Returns:
        repo_scan: A python list containing results of the scan
    """
    # Instantiate GitHub connection
    gh_session = Github(github_pat)
    # Open a CSV for storing results
    csv_file = open("github_audit.csv", mode="w")
    if strict_mode:
        fieldnames = ["Repository", "Default Branch", "Protected?",
                      "PR Reviews", "Dismisses Stale Reviews", "Requires CODEOWNERS",
                      "Approver Count", "Enforce For Admins",
                      "STRICT: Requires Signed Commits", "STRICT: CI Status Checks Required"]
    else:
        fieldnames = ["Repository", "Default Branch", "Protected?",
                      "PR Reviews", "Dismisses Stale Reviews", "Requires CODEOWNERS",
                      "Approver Count", "Enforce For Admins"]
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()
    # Iterate over the list of repos
    for repository in github_repos:
        logging.info("Scanning repo %s", repository)
        # Iterate over PR review requirements
        # Get the default branch which is the one we want to protect
        try:
            default_branch = gh_session.get_repo(repository).default_branch
            logging.info("%s has default branch %s", repository, str(default_branch))
        except GithubException:
            logging.warning("%s has no default branch!", repository)

        # Set the branch object we care about scanning
        try:
            protected_branch = gh_session.get_repo(repository).get_branch(branch=default_branch)
            logging.info("%s:%s has protection!", repository, str(default_branch))
        except GithubException:
            logging.warning("%s:%s has NO protection!", repository, str(default_branch))
            # Write out a basic report of the repo before restarting the loop
            if strict_mode:
                writer.writerow(
                    {
                        "Repository": repository,
                        "Default Branch": default_branch,
                        "Protected?": False,
                        "PR Reviews": False,
                        "Dismisses Stale Reviews": False,
                        "Requires CODEOWNERS": False,
                        "Approver Count": 0,
                        "Enforce For Admins": False,
                        "STRICT: Requires Signed Commits": False,
                        "STRICT: CI Status Checks Required": False
                    }
                )
            else:
                writer.writerow(
                    {
                        "Repository": repository,
                        "Default Branch": default_branch,
                        "Protected?": False,
                        "PR Reviews": False,
                        "Dismisses Stale Reviews": False,
                        "Requires CODEOWNERS": False,
                        "Approver Count": 0,
                        "Enforce For Admins": False
                    }
                )
            continue

        # Iterate over Pull Request review requirements
        try:
            pr_reviews = protected_branch.get_required_pull_request_reviews()
            logging.info("%s:%s requires PR reviews!", repository, str(default_branch))
        except GithubException:
            logging.warning("%s:%s does not require PR reviews!",
                            repository, str(default_branch))
            # Write out a basic report of the repo before restarting the loop
            if strict_mode:
                writer.writerow(
                    {
                        "Repository": repository,
                        "Default Branch": default_branch,
                        "Protected?": False,
                        "PR Reviews": False,
                        "Dismisses Stale Reviews": False,
                        "Requires CODEOWNERS": False,
                        "Approver Count": 0,
                        "Enforce For Admins": False,
                        "STRICT: Requires Signed Commits": False,
                        "STRICT: CI Status Checks Required": False
                    }
                )
            else:
                writer.writerow(
                    {
                        "Repository": repository,
                        "Default Branch": default_branch,
                        "Protected?": False,
                        "PR Reviews": False,
                        "Dismisses Stale Reviews": False,
                        "Requires CODEOWNERS": False,
                        "Approver Count": 0,
                        "Enforce For Admins": False
                    }
                )
            continue

        # If PR reviews are enabled, gather data and continue reporting
        if pr_reviews.dismiss_stale_reviews is False:
            logging.warning("%s:%s does not dismiss stale reviews",
                            repository, str(default_branch))
        if pr_reviews.require_code_owner_reviews is False:
            logging.warning("%s:%s does not require CODEOWNERS",
                            repository, str(default_branch))
        if pr_reviews.required_approving_review_count < MIN_CODE_OWNERS:
            logging.warning("%s:%s does not require at least %s CODEOWNER(s)",
                            repository, str(default_branch), MIN_CODE_OWNERS)

        # Iterate over branch security requirements
        if protected_branch.get_admin_enforcement() is False:
            logging.warning("%s:%s does not enforce the rules for GitHub/repo admins",
                            repository, str(default_branch))
        if strict_mode:
            if protected_branch.get_required_signatures() is False:
                logging.warning("STRICT: %s:%s does not require signed commits",
                                repository, str(default_branch))
            # Check if CI status checks are required
            try:
                _ = protected_branch.get_required_status_checks()
            except GithubException:
                logging.warning("%s:%s does not perform mandatory CI/CD checks",
                                repository, str(default_branch))
            writer.writerow(
                {
                    "Repository": repository,
                    "Default Branch": default_branch,
                    "Protected?": True,
                    "PR Reviews": True,
                    "Dismisses Stale Reviews": pr_reviews.dismiss_stale_reviews,
                    "Requires CODEOWNERS": pr_reviews.require_code_owner_reviews,
                    "Approver Count": pr_reviews.required_approving_review_count,
                    "Enforce For Admins": protected_branch.get_admin_enforcement(),
                    "STRICT: Requires Signed Commits": protected_branch.get_required_signatures(),
                    "STRICT: CI Status Checks Required": protected_branch.get_required_signatures()
                }
            )
        else:
            logging.info("Strict mode checking is not enabled")
            # Write out a complete report of the repo before restarting the loop
            writer.writerow(
                {
                    "Repository": repository,
                    "Default Branch": default_branch,
                    "Protected?": True,
                    "PR Reviews": True,
                    "Dismisses Stale Reviews": pr_reviews.dismiss_stale_reviews,
                    "Requires CODEOWNERS": pr_reviews.require_code_owner_reviews,
                    "Approver Count": pr_reviews.required_approving_review_count,
                    "Enforce For Admins": protected_branch.get_admin_enforcement()
                }
            )


def main(github_pat: str, github_org: str, strict_mode: bool) -> None:
    """
    The main function that triggers and runs the audit functions

    Args:
    github_pat: A GitHub personal access token
    github_org: The short name of a GitHub organization (the "username")
    strict_mode: If true, then have very strict security requirements
    """
    # Configure logging
    logging.basicConfig(level=logging.INFO, datefmt='%m/%d/%G %H:%M:%S',
                        format='%(asctime)s %(levelname)s: %(message)s')
    if strict_mode:
        logging.info("Strict mode is enabled.")
    # Get list of repos
    repo_list = get_org_repos(github_pat, github_org)
    repo_check(github_pat, repo_list, strict_mode)
    #TODO user_audit function to audit the user privileges of each repo
    # 1. Is the user assigned directly?
    # 2. Is the user a collaborator or an org member?
    # 3. List all teams and users on the repo
    sys.exit()


if __name__ == '__main__':
    # This function parses and return arguments passed in
    # Assign description to the help doc
    PARSER = argparse.ArgumentParser(
        description='Check GitHub repos in a GitHub Org for basic security compliance')
    # Add arguments
    PARSER.add_argument(
        '-t', '--githubToken', type=str, help="A GitHub personal access token", required=True
    )
    PARSER.add_argument(
        '-o', '--githubOrg', type=str,
        help="The short name of a GitHub organization (the \"username\")", required=True)
    PARSER.add_argument(
        '-s', '--strictMode', help="Process with very strict requirements",
        required=False, action='store_true'
    )
    # Array for all arguments passed to script
    ARGS = PARSER.parse_args()
    ARG_GH_PAT = ARGS.githubToken
    ARG_GH_ORG = ARGS.githubOrg
    ARG_STRICT = ARGS.strictMode
    main(ARG_GH_PAT, ARG_GH_ORG, ARG_STRICT)
