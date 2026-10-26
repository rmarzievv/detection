# <Rule title>

Based on the Palantir Alerting & Detection Strategy (ADS) framework. One file per rule in `docs/rules/`, same stem as the Sigma file.

## Goal
What attacker behaviour this detects, in one or two sentences.

## Categorization
MITRE ATT&CK tactic and technique IDs.

## Strategy abstract
How the detection works: which telemetry, which fields, what logic.

## Technical context
What the analyst needs to know about the technique to triage the alert.

## Blind spots and assumptions
How an attacker evades this rule; which logging must be enabled for it to work.

## False positives
Known benign activity that triggers the rule and how it is filtered.

## Validation
How to reproduce the behaviour safely (Atomic Red Team test ID, Purple Vector module, or exact command) and what the alert should look like.

## Priority
Severity and why.

## Response
First triage steps when the alert fires.
