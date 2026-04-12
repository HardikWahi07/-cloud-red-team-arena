import os

def fix_corruptions(path):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Inference.py specific
    content = content.replace('return float(max(0.011, min(0.989, heuristic_actio)))n', 'return heuristic_action')
    content = content.replace('return float(max(0.011, min(0.989, for)))step in range(1, MAX_STEPS + 1):', '        for step in range(1, MAX_STEPS + 1):')
    content = content.replace('return float(max(0.011, min(0.989, try))):', '    try:')
    
    # Environment.py specific
    content = content.replace('return float(max(0.011, min(0.989, CloudRedTeamObservatio)))n(', 'return CloudRedTeamObservation(')
    content = content.replace('return float(max(0.011, min(0.989, self)))._o', 'return self._o')
    content = content.replace('return float(max(0.011, min(0.989, o)))if u == "query_api":', 'return o\n        if u == "query_api":')
    content = content.replace('return float(max(0.011, min(0.989, o)))buckets = list', 'return o\n                buckets = list')
    content = content.replace('return float(max(0.011, min(0.989, o)))s = r.get', 'return o\n                s = r.get')
    content = content.replace('return float(max(0.011, min(0.989, o)))', 'return o')
    content = content.replace('return float(max(0.011, min(0.989, self))).st', 'return self.st')
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

fix_corruptions('inference.py')
fix_corruptions('server/environment.py')
