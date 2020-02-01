"use strict";
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
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const core = __importStar(require("@actions/core"));
const github = __importStar(require("@actions/github"));
const LabelSeverityPrefix = 'severity/';
const LabelCritical = LabelSeverityPrefix + 'critical';
const LabelHigh = LabelSeverityPrefix + 'high';
const LabelMedium = LabelSeverityPrefix + 'medium';
const LabelLow = LabelSeverityPrefix + 'low';
const LabelNeedsSeverity = 'needs-severity';
const LabelNeedsCVE = 'needs-cve';
const ManagedLabels = [
    LabelCritical, LabelHigh, LabelMedium, LabelLow,
    LabelNeedsSeverity, LabelNeedsCVE
];
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const client = new github.GitHub(core.getInput('repo-token', { required: true }));
            const context = github.context;
            if (!!context.payload.issue) {
                yield processIssue(client, context.payload.issue);
            }
            else {
                const payload = JSON.stringify(context.payload);
                core.error(`context is missing an issue payload: ${payload}`);
            }
        }
        catch (error) {
            core.error(error);
            core.setFailed(error.message);
        }
    });
}
function processIssue(client, issue) {
    return __awaiter(this, void 0, void 0, function* () {
        updateLabels(client, issue);
    });
}
function updateLabels(client, issue) {
    return __awaiter(this, void 0, void 0, function* () {
        let expected_labels = {}; // Map of expected label -> found
        expected_labels[getSeverity(issue)] = false;
        if (!hasCVE(issue)) {
            expected_labels[LabelNeedsCVE] = false;
        }
        let extra_labels = false; // Whether there are extra managed labels
        let unmanaged_labels = [];
        issue.labels.forEach(element => {
            const label = element.name;
            if (!isManagedLabel(label)) {
                unmanaged_labels.push(label);
            }
            else {
                if (label in expected_labels) {
                    expected_labels[label] = true;
                }
                else {
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
            core.debug(`no label changes required to ${issue.number}`);
            return;
        }
        const desired_labels = [...Object.keys(expected_labels), ...unmanaged_labels];
        yield client.issues.replaceLabels({
            owner: github.context.repo.owner,
            repo: github.context.repo.repo,
            issue_number: issue.number,
            labels: desired_labels
        });
    });
}
function isManagedLabel(label) {
    return ManagedLabels.indexOf(label) > -1;
}
function hasCVE(issue) {
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
function getSeverity(issue) {
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
