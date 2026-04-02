from __future__ import annotations

import json
from typing import Any

import structlog

from auditors.base_auditor import AuditResult, AccessLevel

logger = structlog.get_logger(__name__)

# Map AccessLevel to a human-readable string
_LEVEL_LABEL = {
    AccessLevel.READ: "read",
    AccessLevel.WRITE: "write",
    AccessLevel.ADMIN: "admin",
    AccessLevel.UNKNOWN: "unknown",
}


class PermissionMapper:
    """
    Builds a permission graph from an AuditResult.

    Graph structure::

        {
          "nodes": {
            "<resource_id>": {
              "type": "user|role|service_account|policy",
              "name": "...",
              "provider": "aws|azure"
            }
          },
          "edges": [
            {
              "from": "<principal_id>",
              "to": "<policy_id>",
              "access_level": "read|write|admin|unknown",
              "via": "<policy_name>"
            }
          ]
        }
    """

    def build(self, audit_result: AuditResult) -> dict[str, Any]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []

        provider = audit_result.provider.value

        for user in audit_result.users:
            nodes[user.user_id] = {
                "type": "user",
                "name": user.user_name,
                "provider": provider,
            }
            for policy in user.attached_policies + user.inline_policies:
                pid = policy.policy_id
                if pid not in nodes:
                    nodes[pid] = {
                        "type": "policy",
                        "name": policy.policy_name,
                        "provider": provider,
                    }
                edges.append({
                    "from": user.user_id,
                    "to": pid,
                    "access_level": _LEVEL_LABEL[policy.access_level],
                    "via": policy.policy_name,
                    "actions": policy.actions[:10],  # truncate for readability
                    "resources": policy.resources[:5],
                })

        for role in audit_result.roles:
            nodes[role.role_id] = {
                "type": "role",
                "name": role.role_name,
                "provider": provider,
                "is_cross_account": role.is_cross_account,
                "is_public": role.is_public,
            }
            for policy in role.attached_policies + role.inline_policies:
                pid = policy.policy_id
                if pid not in nodes:
                    nodes[pid] = {
                        "type": "policy",
                        "name": policy.policy_name,
                        "provider": provider,
                    }
                edges.append({
                    "from": role.role_id,
                    "to": pid,
                    "access_level": _LEVEL_LABEL[policy.access_level],
                    "via": policy.policy_name,
                    "actions": policy.actions[:10],
                    "resources": policy.resources[:5],
                })
            for principal in role.trust_principals:
                trust_node_id = f"trust::{principal}"
                if trust_node_id not in nodes:
                    nodes[trust_node_id] = {
                        "type": "trust_principal",
                        "name": principal,
                        "provider": provider,
                    }
                edges.append({
                    "from": trust_node_id,
                    "to": role.role_id,
                    "access_level": "assume_role",
                    "via": "sts:AssumeRole",
                    "actions": ["sts:AssumeRole"],
                    "resources": [role.arn or role.role_id],
                })

        for sa in audit_result.service_accounts:
            nodes[sa.account_id] = {
                "type": "service_account",
                "name": sa.account_name,
                "provider": provider,
            }
            for policy in sa.attached_policies:
                pid = policy.policy_id
                if pid not in nodes:
                    nodes[pid] = {
                        "type": "policy",
                        "name": policy.policy_name,
                        "provider": provider,
                    }
                edges.append({
                    "from": sa.account_id,
                    "to": pid,
                    "access_level": _LEVEL_LABEL[policy.access_level],
                    "via": policy.policy_name,
                    "actions": policy.actions[:10],
                    "resources": policy.resources[:5],
                })

        graph = {"nodes": nodes, "edges": edges}
        logger.info(
            "permission_mapper.built",
            nodes=len(nodes),
            edges=len(edges),
        )
        return graph

    def export_to_dot(self, graph: dict[str, Any]) -> str:
        """Generate a Graphviz DOT string from the permission graph."""
        lines: list[str] = ["digraph IAMPermissions {", '  rankdir=LR;', '  node [shape=box fontname="Helvetica"];']

        type_shapes = {
            "user": "ellipse",
            "role": "diamond",
            "service_account": "parallelogram",
            "policy": "rectangle",
            "trust_principal": "octagon",
        }
        type_colors = {
            "user": "#AED6F1",
            "role": "#A9DFBF",
            "service_account": "#F9E79F",
            "policy": "#F5CBA7",
            "trust_principal": "#D2B4DE",
        }

        nodes = graph.get("nodes", {})
        edges = graph.get("edges", [])

        for node_id, node in nodes.items():
            node_type = node.get("type", "unknown")
            shape = type_shapes.get(node_type, "box")
            color = type_colors.get(node_type, "#FFFFFF")
            safe_id = _dot_escape_id(node_id)
            label = _dot_escape_label(node.get("name", node_id))
            lines.append(
                f'  {safe_id} [label="{label}\\n({node_type})" shape={shape} style=filled fillcolor="{color}"];'
            )

        access_colors = {
            "read": "#2ECC71",
            "write": "#F39C12",
            "admin": "#E74C3C",
            "unknown": "#95A5A6",
            "assume_role": "#8E44AD",
        }

        for edge in edges:
            src = _dot_escape_id(edge["from"])
            dst = _dot_escape_id(edge["to"])
            level = edge.get("access_level", "unknown")
            color = access_colors.get(level, "#95A5A6")
            via = _dot_escape_label(edge.get("via", ""))
            lines.append(f'  {src} -> {dst} [label="{via}" color="{color}"];')

        lines.append("}")
        dot_str = "\n".join(lines)
        logger.info("permission_mapper.dot_exported", lines=len(lines))
        return dot_str

    def to_json(self, graph: dict[str, Any], indent: int = 2) -> str:
        return json.dumps(graph, indent=indent, default=str)


def _dot_escape_id(value: str) -> str:
    """Make a valid DOT node identifier."""
    safe = value.replace(":", "_").replace("/", "_").replace("-", "_").replace(".", "_")
    if safe and safe[0].isdigit():
        safe = "n_" + safe
    return safe


def _dot_escape_label(value: str) -> str:
    return value.replace('"', '\\"').replace("\n", "\\n")
