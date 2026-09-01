#!/usr/bin/env python3
"""Closed cumulative Make-target dispatcher using direct argv only."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

SCHEMA = "harness.planeon.ai/make-target-descriptor/v1alpha1"
PACKET = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
TARGET = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
VARIABLE = re.compile(r"^[A-Z][A-Z0-9_]*$")
MAKE_ASSIGNMENT = re.compile(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=")
ALLOWED_VARIABLES = {"BACKEND", "CAMPAIGN", "MODULE", "PACK", "PROVIDERS"}
FORBIDDEN_EXECUTABLES = {"bash", "dash", "env", "sh", "zsh"}


class DescriptorError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DescriptorError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _object(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise DescriptorError(f"object required: {context}")
    return value


@dataclass(frozen=True, slots=True)
class Rule:
    packet_id: str
    target: str
    variables: Mapping[str, frozenset[str]]
    commands: tuple[tuple[str | tuple[str, str], ...], ...]

    def matches(self, supplied: Mapping[str, str]) -> bool:
        return set(supplied) == set(self.variables) and all(
            supplied[name] in values for name, values in self.variables.items()
        )

    def render(self, supplied: Mapping[str, str]) -> tuple[tuple[str, ...], ...]:
        return tuple(
            tuple(supplied[item[1]] if isinstance(item, tuple) else item for item in command)
            for command in self.commands
        )


def _parse_variables(value: object, context: str) -> Mapping[str, frozenset[str]]:
    raw = _object(value, context)
    result: dict[str, frozenset[str]] = {}
    for name, raw_rule in raw.items():
        if VARIABLE.fullmatch(name) is None or name not in ALLOWED_VARIABLES:
            raise DescriptorError(f"undeclared variable: {name}")
        rule = _object(raw_rule, f"{context}/{name}")
        values = [rule["const"]] if set(rule) == {"const"} else rule.get("enum") if set(rule) == {"enum"} else None
        if not isinstance(values, list) or not values or not all(isinstance(item, str) and item for item in values) or len(values) != len(set(values)):
            raise DescriptorError(f"variable rule is not closed: {context}/{name}")
        result[name] = frozenset(values)
    return result


def _parse_commands(value: object, variables: Mapping[str, frozenset[str]], context: str) -> tuple[tuple[str | tuple[str, str], ...], ...]:
    if not isinstance(value, list) or not value:
        raise DescriptorError(f"argvTemplate is empty: {context}")
    result: list[tuple[str | tuple[str, str], ...]] = []
    for raw_command in value:
        if not isinstance(raw_command, list) or not raw_command:
            raise DescriptorError(f"argv command is empty: {context}")
        command: list[str | tuple[str, str]] = []
        for item in raw_command:
            if isinstance(item, str) and item and "\x00" not in item and "\n" not in item:
                command.append(item)
            elif isinstance(item, dict) and set(item) == {"variable"} and item["variable"] in variables:
                command.append(("variable", str(item["variable"])))
            else:
                raise DescriptorError(f"argv argument is not closed: {context}")
        executable = command[0]
        if not isinstance(executable, str) or Path(executable).name in FORBIDDEN_EXECUTABLES:
            raise DescriptorError(f"shell transport is forbidden: {context}")
        result.append(tuple(command))
    return tuple(result)


def _overlap(left: Rule, right: Rule) -> bool:
    return (
        left.packet_id == right.packet_id
        and left.target == right.target
        and set(left.variables) == set(right.variables)
        and all(left.variables[name] & right.variables[name] for name in left.variables)
    )


def load_rules(directory: Path) -> tuple[Rule, ...]:
    if not directory.is_dir() or directory.is_symlink():
        raise DescriptorError("descriptor directory is absent or linked")
    rules: list[Rule] = []
    owners: set[str] = set()
    for path in sorted(directory.glob("*.json"), key=lambda item: item.name):
        if path.is_symlink() or not path.is_file():
            raise DescriptorError("descriptor must be a regular file")
        try:
            descriptor = _object(
                json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object),
                path.name,
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise DescriptorError(f"invalid descriptor: {path.name}") from exc
        if set(descriptor) != {"schemaVersion", "packetId", "targets"} or descriptor["schemaVersion"] != SCHEMA:
            raise DescriptorError(f"closed descriptor fields are invalid: {path.name}")
        owner = descriptor["packetId"]
        if not isinstance(owner, str) or PACKET.fullmatch(owner) is None or path.name != f"{owner.lower()}.json":
            raise DescriptorError(f"owner or filename mismatch: {path.name}")
        if owner in owners:
            raise DescriptorError(f"duplicate owner descriptor: {owner}")
        owners.add(owner)
        targets = descriptor["targets"]
        if not isinstance(targets, list) or not targets:
            raise DescriptorError(f"descriptor has no targets: {path.name}")
        for index, raw_target in enumerate(targets):
            target = _object(raw_target, f"{path.name}/{index}")
            if set(target) != {"name", "acceptedVariables", "argvTemplate"}:
                raise DescriptorError(f"target fields are not closed: {path.name}/{index}")
            name = target["name"]
            if not isinstance(name, str) or TARGET.fullmatch(name) is None:
                raise DescriptorError(f"invalid target name: {path.name}/{index}")
            variables = _parse_variables(target["acceptedVariables"], f"{path.name}/{name}")
            candidate = Rule(owner, name, variables, _parse_commands(target["argvTemplate"], variables, f"{path.name}/{name}"))
            if any(_overlap(existing, candidate) for existing in rules):
                raise DescriptorError(f"duplicate or overlapping target rule: {owner}/{name}")
            rules.append(candidate)
    if not rules:
        raise DescriptorError("no target descriptors were found")
    return tuple(sorted(rules, key=lambda item: (item.packet_id, item.target)))


def dispatch(target: str, supplied: Mapping[str, str], directory: Path) -> int:
    if TARGET.fullmatch(target) is None:
        raise DescriptorError("target name is invalid")
    matches = [rule for rule in load_rules(directory) if rule.target == target and rule.matches(supplied)]
    if not matches:
        raise DescriptorError(f"zero applicable handlers: {target}")
    if len({rule.packet_id for rule in matches}) != len(matches):
        raise DescriptorError(f"multiple applicable handlers from one packet: {target}")
    for rule in matches:
        for command in rule.render(supplied):
            print(f"make-handler packet={rule.packet_id} argv={json.dumps(command, separators=(',', ':'))}", flush=True)
            completed = subprocess.run(command, shell=False, check=False)
            if completed.returncode:
                return completed.returncode
    return 0


def supplied_variables(environment: Mapping[str, str]) -> dict[str, str]:
    overrides = environment.get("MAKEOVERRIDES", "")
    names = set(MAKE_ASSIGNMENT.findall(overrides))
    unknown = names - ALLOWED_VARIABLES
    if unknown:
        raise DescriptorError(f"undeclared Make variable: {sorted(unknown)[0]}")
    return {name: environment[name] for name in ALLOWED_VARIABLES if name in names and environment.get(name)}


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print("one Make target is required", file=sys.stderr)
        return 2
    try:
        return dispatch(arguments[0], supplied_variables(os.environ), Path(__file__).with_name("targets"))
    except DescriptorError as exc:
        print(f"Make dispatch refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
