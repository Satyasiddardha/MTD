"""
MTD-HealthNet Threat Model Diagram Generator (Graphviz Version)
Generates publication-quality cybersecurity architecture diagrams using Graphviz
Produces cleaner, more professional output suitable for IEEE/ACM publications
"""

try:
    from graphviz import Digraph
    GRAPHVIZ_AVAILABLE = True
except ImportError:
    GRAPHVIZ_AVAILABLE = False
    print("Warning: graphviz not installed. Run: pip install graphviz")
    print("Also ensure Graphviz system package is installed:")
    print("  macOS: brew install graphviz")
    print("  Ubuntu: sudo apt install graphviz")

def create_threat_model_graphviz():
    """Generate threat model using Graphviz for publication quality"""

    if not GRAPHVIZ_AVAILABLE:
        print("ERROR: Graphviz not available. Install with:")
        print("  pip install graphviz")
        print("  brew install graphviz  # or apt install graphviz")
        return None

    # Create directed graph
    dot = Digraph(comment='MTD-HealthNet Threat Model',
                  format='png',
                  engine='dot')

    # Graph attributes for professional layout
    dot.attr(rankdir='TB',  # Top to bottom
             splines='ortho',  # Orthogonal edges
             nodesep='0.8',
             ranksep='1.2',
             fontname='Arial',
             fontsize='11',
             bgcolor='white',
             dpi='300')

    dot.attr('node',
             fontname='Arial',
             fontsize='10',
             shape='box',
             style='rounded,filled',
             margin='0.3,0.2')

    dot.attr('edge',
             fontname='Arial',
             fontsize='9',
             penwidth='2.0')

    # ==================== NODES ====================

    # Title (invisible node for positioning)
    dot.node('title', label='MTD-HealthNet Threat Model\nMoving Target Defense Architecture',
             shape='plaintext', fontsize='16', fontcolor='#1A1A1A', style='')

    # Layer 1: Threat Actor
    dot.node('attacker',
             label='🎭 ATTACKER\n━━━━━━━━━━\n• Network Scanning\n• Port Enumeration\n• IP Spoofing\n• Payload Injection\n• Session Hijacking',
             fillcolor='#FF6B6B',
             fontcolor='white',
             color='#C92A2A',
             penwidth='3')

    # Attack attempts
    dot.node('recon', label='❌ Reconnaissance\nScanning 172.16.0.x',
             fillcolor='#FA5252', fontcolor='white', color='#C92A2A',
             style='dashed,rounded,filled', penwidth='2')

    dot.node('spoof', label='❌ IP Spoofing\nMasquerade Attack',
             fillcolor='#FA5252', fontcolor='white', color='#C92A2A',
             style='dashed,rounded,filled', penwidth='2')

    dot.node('inject', label='❌ Payload Injection\nMalicious Packets',
             fillcolor='#FA5252', fontcolor='white', color='#C92A2A',
             style='dashed,rounded,filled', penwidth='2')

    # Layer 2: External Network
    dot.node('internet',
             label='🌐 INTERNET\nExternal Network',
             fillcolor='#FFD93D',
             color='#F08C00')

    dot.node('client',
             label='💻 LEGITIMATE CLIENT\nHealthcare Workstation',
             fillcolor='#FFD93D',
             color='#F08C00')

    # Layer 3: MTD Engine
    dot.node('mtd',
             label='🔄 MTD ENGINE\n━━━━━━━━━━\nZone-Based IP Hopping:\n• High Risk: 120s interval\n• Med Risk: 100s interval\n• Low Risk: 80s interval\n━━━━━━━━━━\nPort Randomization\nFlow Table Updates',
             fillcolor='#339AF0',
             fontcolor='white',
             color='#1971C2',
             penwidth='3')

    # Layer 4: NAT Tables
    dot.node('dnat',
             label='📥 DNAT TABLE\nPublic → Private\n172.16.0.y → 10.0.0.x',
             fillcolor='#51CF66',
             color='#2F9E44')

    dot.node('snat',
             label='📤 SNAT TABLE\nPrivate → Public\n10.0.0.x → 172.16.0.y',
             fillcolor='#51CF66',
             color='#2F9E44')

    # Layer 5: Policy Engine
    dot.node('policy',
             label='🛡️ POLICY ENGINE\n━━━━━━━━━━\nZone ACL Rules:\n• High → ALL (Allow)\n• Medium → Low (Allow)\n• Low → ALL (Deny)\n━━━━━━━━━━\nRate Limiting\nAnomaly Detection',
             fillcolor='#51CF66',
             color='#2F9E44')

    # Layer 6: Cryptographic Operations
    dot.node('encrypt',
             label='🔐 AES-256-GCM\nENCRYPTION\n━━━━━━━━━━\nRandom Session Keys\nIV Generation\nAEAD Mode',
             fillcolor='#DA77F2',
             fontcolor='white',
             color='#9C36B5')

    dot.node('decrypt',
             label='🔓 AES-256-GCM\nDECRYPTION\n━━━━━━━━━━\nKey Derivation\nIV Validation\nTag Verification',
             fillcolor='#DA77F2',
             fontcolor='white',
             color='#9C36B5')

    # Layer 7: Integrity Verification
    dot.node('hash_gen',
             label='#️⃣ HASH GENERATION\nSHA-256\nPayload Integrity',
             fillcolor='#DA77F2',
             fontcolor='white',
             color='#9C36B5')

    dot.node('hash_verify',
             label='✅ HASH VERIFICATION\nCompare Hashes\nDetect Tampering',
             fillcolor='#DA77F2',
             fontcolor='white',
             color='#9C36B5')

    # Layer 8: Internal Network
    dot.node('hospital',
             label='🏥 HOSPITAL SERVER\n━━━━━━━━━━\nPrivate IP: 10.0.0.x\nPublic IP: 172.16.0.y (rotating)\n━━━━━━━━━━\nEHR Database\nMedical Imaging\nPatient Records',
             fillcolor='#69DB7C',
             color='#2B8A3E',
             penwidth='3')

    # ==================== EDGES: NORMAL DATA FLOW ====================

    # Forward path (client to server) - GREEN
    dot.edge('client', 'internet', label='① Request\ndst: 172.16.0.50',
             color='#2F9E44', fontcolor='#2F9E44')

    dot.edge('internet', 'mtd', label='② Route to MTD',
             color='#2F9E44', fontcolor='#2F9E44')

    dot.edge('mtd', 'policy', label='③ Check Policy',
             color='#2F9E44', fontcolor='#2F9E44')

    dot.edge('policy', 'dnat', label='④ ✅ ALLOW\n(zone check passed)',
             color='#2F9E44', fontcolor='#2F9E44')

    dot.edge('dnat', 'decrypt', label='⑤ Translate\n172.16.0.50→10.0.0.2',
             color='#2F9E44', fontcolor='#2F9E44')

    dot.edge('decrypt', 'hash_verify', label='⑥ Decrypt Payload',
             color='#2F9E44', fontcolor='#2F9E44')

    dot.edge('hash_verify', 'hospital', label='⑦ Verify Integrity',
             color='#2F9E44', fontcolor='#2F9E44')

    # Return path (server to client) - BLUE
    dot.edge('hospital', 'hash_gen', label='⑧ Response Data',
             color='#1971C2', fontcolor='#1971C2')

    dot.edge('hash_gen', 'encrypt', label='⑨ Generate Hash',
             color='#1971C2', fontcolor='#1971C2')

    dot.edge('encrypt', 'snat', label='⑩ Encrypt with AES-GCM',
             color='#1971C2', fontcolor='#1971C2')

    dot.edge('snat', 'mtd', label='⑪ Translate\n10.0.0.2→172.16.0.75\n(NEW IP!)',
             color='#1971C2', fontcolor='#1971C2', style='bold')

    dot.edge('mtd', 'internet', label='⑫ IP Hopped!\nsrc: 172.16.0.75',
             color='#1971C2', fontcolor='#1971C2', style='bold')

    dot.edge('internet', 'client', label='⑬ Encrypted Response',
             color='#1971C2', fontcolor='#1971C2')

    # ==================== EDGES: ATTACK FLOWS (BLOCKED) ====================

    # Attack 1: Reconnaissance blocked
    dot.edge('attacker', 'recon', color='#FA5252', style='dashed')
    dot.edge('recon', 'internet', label='Scan 172.16.0.50',
             color='#FA5252', fontcolor='#FA5252', style='dashed')
    dot.edge('internet', 'mtd', label='IP hopped to 172.16.0.75',
             color='#FA5252', fontcolor='#FA5252', style='dashed')
    dot.edge('mtd', 'recon', label='❌ Stale IP',
             color='#FA5252', fontcolor='#FA5252', style='dashed',
             constraint='false')

    # Attack 2: Spoofing blocked
    dot.edge('attacker', 'spoof', color='#FA5252', style='dashed')
    dot.edge('spoof', 'policy', label='Spoof Source IP',
             color='#FA5252', fontcolor='#FA5252', style='dashed')
    dot.edge('policy', 'spoof', label='❌ Zone Violation',
             color='#FA5252', fontcolor='#FA5252', style='dashed',
             constraint='false')

    # Attack 3: Injection blocked
    dot.edge('attacker', 'inject', color='#FA5252', style='dashed')
    dot.edge('inject', 'hash_verify', label='Malicious Payload',
             color='#FA5252', fontcolor='#FA5252', style='dashed')
    dot.edge('hash_verify', 'inject', label='❌ Hash Mismatch',
             color='#FA5252', fontcolor='#FA5252', style='dashed',
             constraint='false')

    # ==================== EDGES: MTD CONTROL LOOP ====================

    dot.edge('mtd', 'snat', label='Periodic Shuffle\n(every 80-120s)',
             color='#868E96', fontcolor='#495057', style='dotted',
             constraint='false', dir='both')

    dot.edge('mtd', 'dnat', label='Update Mappings',
             color='#868E96', fontcolor='#495057', style='dotted',
             constraint='false', dir='both')

    # ==================== SUBGRAPHS FOR LAYOUT ====================

    # Group threat sources
    with dot.subgraph(name='cluster_threats') as c: #type: ignore
        c.attr(label='🎯 ATTACK SURFACE', style='dashed',
               color='#C92A2A', fontsize='12', fontcolor='#C92A2A')
        c.node('attacker')
        c.node('recon')
        c.node('spoof')
        c.node('inject')

    # Group external network
    with dot.subgraph(name='cluster_external') as c: #type: ignore
        c.attr(label='🌍 EXTERNAL NETWORK', style='dashed',
               color='#F08C00', fontsize='12', fontcolor='#F08C00')
        c.node('internet')
        c.node('client')

    # Group defense layer
    with dot.subgraph(name='cluster_defense') as c: #type: ignore
        c.attr(label='🛡️ DEFENSE IN DEPTH', style='filled',
               color='#2F9E44', fillcolor='#F0FFF4', fontsize='12',
               fontcolor='#2F9E44')
        c.node('mtd')
        c.node('policy')
        c.node('dnat')
        c.node('snat')

    # Group crypto layer
    with dot.subgraph(name='cluster_crypto') as c: #type: ignore
        c.attr(label='🔒 CRYPTOGRAPHIC PROTECTION', style='filled',
               color='#9C36B5', fillcolor='#F8F0FC', fontsize='12',
               fontcolor='#9C36B5')
        c.node('encrypt')
        c.node('decrypt')
        c.node('hash_gen')
        c.node('hash_verify')

    # Group internal network
    with dot.subgraph(name='cluster_internal') as c: #type: ignore
        c.attr(label='🔒 TRUSTED INTERNAL NETWORK', style='filled',
               color='#2B8A3E', fillcolor='#EBFBEE', fontsize='12',
               fontcolor='#2B8A3E')
        c.node('hospital')

    return dot

def create_simplified_version():
    """Create a simplified version for presentations"""

    if not GRAPHVIZ_AVAILABLE:
        return None

    dot = Digraph(comment='MTD-HealthNet Simplified',
                  format='png',
                  engine='dot')

    dot.attr(rankdir='LR', splines='spline', fontname='Arial',
             fontsize='11', bgcolor='white', dpi='300')
    dot.attr('node', fontname='Arial', fontsize='10',
             shape='box', style='rounded,filled')
    dot.attr('edge', fontname='Arial', fontsize='9', penwidth='2')

    # Simplified nodes
    dot.node('client', '💻\nClient', fillcolor='#FFD93D')
    dot.node('mtd', '🔄\nMTD\nEngine', fillcolor='#339AF0', fontcolor='white')
    dot.node('nat', '🔀\nNAT\nLayer', fillcolor='#51CF66')
    dot.node('crypto', '🔐\nCrypto\nLayer', fillcolor='#DA77F2', fontcolor='white')
    dot.node('server', '🏥\nHospital\nServer', fillcolor='#69DB7C')
    dot.node('attacker', '🎭\nAttacker', fillcolor='#FF6B6B', fontcolor='white')

    # Normal flow
    dot.edge('client', 'mtd', label='Request', color='#2F9E44')
    dot.edge('mtd', 'nat', label='IP Hopping', color='#2F9E44')
    dot.edge('nat', 'crypto', label='Translation', color='#2F9E44')
    dot.edge('crypto', 'server', label='Encrypted', color='#2F9E44')
    dot.edge('server', 'client', label='Response', color='#1971C2', style='dashed')

    # Attack flow (blocked)
    dot.edge('attacker', 'mtd', label='Recon', color='#FA5252', style='dashed')
    dot.edge('mtd', 'attacker', label='❌ Blocked', color='#FA5252', style='dashed')

    # MTD feedback
    dot.edge('mtd', 'nat', label='Periodic\nShuffle', color='#868E96',
             style='dotted', constraint='false', dir='both')

    return dot

def main():
    """Generate threat model diagrams"""

    print("=" * 60)
    print("MTD-HealthNet Threat Model Diagram Generator (Graphviz)")
    print("=" * 60)

    if not GRAPHVIZ_AVAILABLE:
        print("\n❌ ERROR: Graphviz not available")
        print("\nInstall with:")
        print("  pip install graphviz")
        print("  brew install graphviz  # macOS")
        print("  sudo apt install graphviz  # Ubuntu")
        return

    print("\n📊 Generating comprehensive threat model...")
    dot = create_threat_model_graphviz()

    if dot:
        # Save in multiple formats
        formats = ['png', 'pdf', 'svg']
        for fmt in formats:
            filename = f'threat_model_graphviz.{fmt}'
            dot.format = fmt
            dot.render('threat_model_graphviz', cleanup=True, format=fmt)
            print(f"  ✓ Saved: {filename}")

    print("\n📊 Generating simplified version...")
    dot_simple = create_simplified_version()

    if dot_simple:
        formats = ['png', 'pdf']
        for fmt in formats:
            filename = f'threat_model_simplified.{fmt}'
            dot_simple.format = fmt
            dot_simple.render('threat_model_simplified', cleanup=True, format=fmt)
            print(f"  ✓ Saved: {filename}")

    print("\n" + "=" * 60)
    print("✅ Diagram generation complete!")
    print("=" * 60)
    print("\nFiles created:")
    print("  Comprehensive version:")
    print("    - threat_model_graphviz.png (presentation)")
    print("    - threat_model_graphviz.pdf (academic papers)")
    print("    - threat_model_graphviz.svg (vector editing)")
    print("\n  Simplified version:")
    print("    - threat_model_simplified.png (overview)")
    print("    - threat_model_simplified.pdf (slides)")
    print("\nRecommendation: Use the PDF version for IEEE/ACM papers")

if __name__ == '__main__':
    main()
