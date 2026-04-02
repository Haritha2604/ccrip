"""
correlation.py
--------------
CORRELATION ENGINE — Multi-credential analysis.

When a repository leaks more than one credential, this module:
  1. Groups credentials by AWS account ID (from STS validation)
  2. Identifies shared risks across credentials
  3. Builds a simple attack graph (nodes + edges) representing
     how an attacker could chain the credentials together
"""


def correlate_credentials(analyzed: list[dict]) -> dict:
    """
    Cross-correlate all analyzed credentials.

    Each item in `analyzed` must contain:
        access_key, validation (dict), permissions (list), risk_level, attack_paths

    Returns:
        {
            "accounts":           {account_id: [access_keys]},
            "shared_risks":       [str],
            "attack_graph_nodes": [str],
            "attack_graph_edges": [[source, target, label], ...],
            "summary":            str
        }
    """
    if not analyzed:
        return {
            'accounts':           {},
            'shared_risks':       [],
            'attack_graph_nodes': [],
            'attack_graph_edges': [],
            'summary':            'No credentials to correlate.',
        }

    # ── 1. Group by AWS account ───────────────────────────────────────────────
    accounts: dict[str, list[str]] = {}
    for cred in analyzed:
        account_id = (cred.get('validation') or {}).get('account_id') or 'unknown'
        accounts.setdefault(account_id, []).append(cred['access_key'])

    # ── 2. Shared risk detection ──────────────────────────────────────────────
    shared_risks: list[str] = []
    all_permissions: list[str] = []
    for cred in analyzed:
        all_permissions.extend(cred.get('permissions', []))

    real_accounts = [a for a in accounts if a != 'unknown']

    if len(real_accounts) == 1 and len(analyzed) > 1:
        shared_risks.append(
            'Multiple credentials belong to the SAME AWS account — '
            'full account compromise is likely.'
        )

    if 'IAM_ACCESS' in all_permissions or 'FULL_ACCESS' in all_permissions:
        shared_risks.append(
            'At least one credential has IAM access — an attacker can '
            'pivot to any user or role in the compromised account.'
        )

    critical_count = sum(
        1 for c in analyzed if c.get('risk_level') == 'CRITICAL'
    )
    if critical_count > 1:
        shared_risks.append(
            f'{critical_count} CRITICAL credentials found — '
            'treat the entire AWS account as compromised.'
        )

    active_count = sum(
        1 for c in analyzed
        if (c.get('validation') or {}).get('status') == 'ACTIVE'
    )
    if active_count > 1:
        shared_risks.append(
            f'{active_count} credentials are still ACTIVE — '
            'each provides an independent attacker entry point.'
        )

    # ── 3. Build attack graph ─────────────────────────────────────────────────
    nodes: list[str] = ['Attacker']
    edges: list[list[str]] = []

    for cred in analyzed:
        key_label = cred['access_key'][:12] + '...'
        if key_label not in nodes:
            nodes.append(key_label)
        edges.append(['Attacker', key_label, 'uses'])

        for ap in cred.get('attack_paths', []):
            attack_node = ap['attack']
            if attack_node not in nodes:
                nodes.append(attack_node)
            edges.append([key_label, attack_node, 'enables'])

    # ── 4. Build summary sentence ─────────────────────────────────────────────
    summary = (
        f"{len(analyzed)} credential(s) found across "
        f"{len(real_accounts)} AWS account(s). "
        f"{active_count} currently active."
    )
    if shared_risks:
        summary += f' {len(shared_risks)} cross-credential risk(s) identified.'

    return {
        'accounts':           accounts,
        'shared_risks':       shared_risks,
        'attack_graph_nodes': nodes,
        'attack_graph_edges': edges,
        'summary':            summary,
    }
