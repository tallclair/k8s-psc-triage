/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import * as core from '@actions/core';
import * as github from '@actions/github';
import * as Octokit from '@octokit/rest';

type Issue = Octokit.IssuesListForRepoResponseItem;

const LabelSeverityPrefix = 'severity/'
const LabelCritical = LabelSeverityPrefix + 'critical'
const LabelHigh = LabelSeverityPrefix + 'high'
const LabelMedium = LabelSeverityPrefix + 'medium'
const LabelLow = LabelSeverityPrefix + 'low'

const LabelNeedsSeverity = 'needs-severity'
const LabelNeedsCVE = 'needs-cve'

const ManagedLabels = [
  LabelCritical, LabelHigh, LabelMedium, LabelLow,
  LabelNeedsSeverity, LabelNeedsCVE
];

async function run() {
  try {
    const client = new github.GitHub(
      core.getInput('repo-token', {required: true})
    );
    const context = github.context;

    if (!!context.payload.issue) {
      await processIssue(client, context.payload.issue as Issue);
    } else {
      const payload = JSON.stringify(context.payload);
      core.error(`context is missing an issue payload: ${payload}`);
    }
  } catch (error) {
    core.error(error);
    core.setFailed(error.message);
  }
}

async function processIssue(
  client: github.GitHub,
  issue: Issue
) {
  updateLabels(client, issue);
}

async function updateLabels(
  client: github.GitHub,
  issue: Issue
) {
  let expected_labels = {}; // Map of expected label -> found
  expected_labels[getSeverity(issue)] = false;
  if (!hasCVE(issue)) {
    expected_labels[LabelNeedsCVE] = false;
  }
  let extra_labels = false; // Whether there are extra managed labels
  let unmanaged_labels: string[] = [];
  issue.labels.forEach(element => {
    const label = element.name;
    if (!isManagedLabel(label)) {
      unmanaged_labels.push(label)
    } else {
      if (label in expected_labels) {
        expected_labels[label] = true;
      } else {
        extra_labels = true;
      }
    }
  });
  let missing_labels = false;
  for (let label in expected_labels) {
    if (!expected_labels[label]) {
      missing_labels = true;
      break;
    }
  }
  if (!missing_labels && !extra_labels) {
    core.debug(`no label changes required to ${issue.number}`)
    return
  }

  const desired_labels = [...Object.keys(expected_labels), ...unmanaged_labels];
  await client.issues.replaceLabels({
    owner: github.context.repo.owner,
    repo: github.context.repo.repo,
    issue_number: issue.number,
    labels: desired_labels
  });
}

function isManagedLabel(label: string): boolean {
  return ManagedLabels.indexOf(label) > -1;
}

function hasCVE(issue: Issue): boolean {
  const cve_match = issue.body.match(/CVE: ([\w-]+)/i);
  if (!cve_match || cve_match.length < 2) {
    return false;
  }
  const cve = cve_match[1].trim();
  if (cve.toUpperCase() == 'TBD' || cve == '') {
    return false;
  }
  return true;
}

function getSeverity(issue: Issue): string {
  const severity_match = issue.body.match(/Severity: ([\w-]+)/i);
  if (!severity_match || severity_match.length < 2) {
    return LabelNeedsSeverity;
  }
  const severity = severity_match[1].toLowerCase().trim();
  switch (severity) {
    case 'critical':
      return LabelCritical;
    case 'high':
      return LabelHigh;
    case 'medium':
      return LabelMedium;
    case 'low':
      return LabelLow;
    default:
      return LabelNeedsSeverity;
  }
}

run();
