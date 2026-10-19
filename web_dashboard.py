#!/usr/bin/env python3
"""
Web Dashboard for ShieldFi — browser preview version of the CustomTkinter desktop app.
Serves same 3 modules but over HTTP so you can see it in Arena Live Preview.

Run: python web_dashboard.py --port 8000
Then open Live Preview link.
"""
import os, sys, json, argparse
from flask import Flask, render_template_string, request, jsonify

# Ensure shieldfi package importable
sys.path.insert(0, os.path.dirname(__file__))

from shieldfi.scanner.mock import MockScanner
from shieldfi.analysis.risk_audit import PassiveRiskAuditor
from shieldfi.analysis.evil_twin import EvilTwinDetector
from shieldfi.active.fingerprint import ActiveFingerprint

app = Flask(__name__)

TRUSTED_PATH = os.path.join("config", "trusted_networks.json")
trusted = []
if os.path.exists(TRUSTED_PATH):
    try:
        with open(TRUSTED_PATH) as f:
            trusted = json.load(f).get("trusted_networks", [])
    except: pass

auditor = PassiveRiskAuditor(trusted_networks=trusted)
detector = EvilTwinDetector()
active_checker = ActiveFingerprint()

# auto-detect OS scanner for live mode
def get_live_networks():
    import platform
    system = platform.system().lower()
    try:
        if system == "linux":
            from shieldfi.scanner.linux import LinuxScanner
            s = LinuxScanner()
            if s.is_available():
                nets = s.scan()
                if nets: return nets, "linux (nmcli/iwlist)"
        elif system == "windows":
            from shieldfi.scanner.windows import WindowsScanner
            s = WindowsScanner()
            if s.is_available():
                return s.scan(), "windows (netsh)"
        elif system == "darwin":
            from shieldfi.scanner.macos import MacOSScanner
            s = MacOSScanner()
            if s.is_available():
                return s.scan(), "macOS (airport)"
    except Exception as e:
        return [], f"error: {e}"
    return [], "no adapter / headless"

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ShieldFi — Web Dashboard</title>
<style>
  :root { --bg:#0f1117; --card:#1a1d26; --border:#2a2e3a; --muted:#9aa0b5; --text:#e6e8ef; --accent:#3b82f6; --green:#10b981; --greenbg:#064e3b; --yellow:#f59e0b; --yellowbg:#78350f; --red:#ef4444; --redbg:#7f1d1d; }
  *{box-sizing:border-box} body{margin:0;font-family:Segoe UI,Inter,system-ui;background:var(--bg);color:var(--text)}
  a{color:var(--accent)}
  .top{padding:18px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;border-bottom:1px solid var(--border);position:sticky;top:0;background:rgba(15,17,23,0.9);backdrop-filter:blur(8px);z-index:10}
  .brand{font-size:22px;font-weight:800;letter-spacing:0.5px} .brand span{color:var(--accent)}
  .badge{padding:4px 10px;border-radius:20px;font-size:12px;font-weight:700;border:1px solid var(--border);background:var(--card);color:var(--muted)}
  .controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-left:auto}
  select,button{padding:8px 12px;border-radius:10px;border:1px solid var(--border);background:var(--card);color:var(--text);font-weight:600;cursor:pointer}
  button.primary{background:var(--accent);border-color:var(--accent);color:white}
  button:active{transform:scale(0.98)}
  .layout{display:grid;grid-template-columns:1.1fr 0.9fr;gap:16px;padding:16px;max-width:1200px;margin:0 auto}
  @media(max-width:900px){.layout{grid-template-columns:1fr}}
  .card{background:var(--card);border:1px solid var(--border);border-radius:16px;overflow:hidden}
  .card h3{margin:0;padding:14px 16px;font-size:14px;letter-spacing:0.6px;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}
  .shield{padding:18px;display:flex;flex-direction:column;align-items:center;gap:12px;text-align:center}
  .orb{width:140px;height:140px;border-radius:50%;display:grid;place-items:center;font-size:56px;border:4px solid;position:relative;overflow:hidden}
  .orb.green{border-color:var(--green);background:radial-gradient(circle at 30% 30%, var(--greenbg), transparent 70%);color:var(--green);box-shadow:0 0 40px rgba(16,185,129,0.35)}
  .orb.yellow{border-color:var(--yellow);background:radial-gradient(circle at 30% 30%, var(--yellowbg), transparent 70%);color:var(--yellow);box-shadow:0 0 40px rgba(245,158,11,0.35)}
  .orb.red{border-color:var(--red);background:radial-gradient(circle at 30% 30%, var(--redbg), transparent 70%);color:var(--red);box-shadow:0 0 40px rgba(239,68,68,0.45); animation:pulse 1s infinite alternate}
  @keyframes pulse{from{transform:scale(1)}to{transform:scale(1.04)}}
  .level{font-size:22px;font-weight:900;letter-spacing:1px}
  .sub{color:var(--muted);font-size:13px}
  .score{font-family:ui-monospace,Consolas,monospace;background:var(--bg);border:1px solid var(--border);padding:6px 10px;border-radius:8px;font-weight:700}
  .ap-list{max-height:520px;overflow:auto}
  .ap{padding:12px 14px;border-bottom:1px solid var(--border);display:flex;flex-direction:column;gap:6px}
  .ap:last-child{border-bottom:none}
  .ap-top{display:flex;justify-content:space-between;gap:10px;align-items:center}
  .ssid{font-weight:700;display:flex;gap:6px;align-items:center}
  .meta{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--muted)}
  .pills{display:flex;gap:6px;flex-wrap:wrap}
  .pill{padding:3px 8px;border-radius:20px;font-size:11px;font-weight:800;border:1px solid}
  .pill.Open,.pill.WEP,.pill.WPA-TKIP{background:var(--redbg);color:var(--red);border-color:var(--red)}
  .pill.WPA2,.pill.WPA{background:var(--yellowbg);color:var(--yellow);border-color:var(--yellow)}
  .pill.WPA3{background:var(--greenbg);color:var(--green);border-color:var(--green)}
  .flag{padding:3px 8px;border-radius:8px;background:var(--redbg);color:var(--red);font-weight:800;font-size:11px;border:1px solid var(--red)}
  .explain{padding:10px;display:flex;flex-direction:column;gap:8px;max-height:280px;overflow:auto}
  .reason{padding:10px 12px;border-radius:10px;background:var(--bg);border-left:4px solid var(--border);font-size:13px;line-height:1.4}
  .reason.red{border-left-color:var(--red)}
  .reason.yellow{border-left-color:var(--yellow)}
  .reason.green{border-left-color:var(--green)}
  .kvs{display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:12px}
  .kv{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:10px}
  .kv b{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px}
  .kv div{font-family:ui-monospace,Consolas,monospace;font-size:12px;margin-top:6px;word-break:break-all}
  .sig{font-family:ui-monospace,Consolas,monospace;letter-spacing:1px}
  .foot{padding:12px 16px;color:var(--muted);font-size:12px;border-top:1px solid var(--border);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
</style>
</head>
<body>
<div class="top">
  <div class="brand">🛡️ ShieldFi <span>— Wi-Fi Security Auditor</span></div>
  <div class="badge">Defensive only • No deauth / no sniffing</div>
  <div class="controls">
    <label style="font-size:13px;color:var(--muted)">Mode</label>
    <select id="mode">
      <option value="mock">Mock / Demo</option>
      <option value="live">Live OS (nmcli/netsh)</option>
    </select>
    <select id="scenario">
      <option value="evil_twin">evil_twin (Red)</option>
      <option value="normal">normal (Green)</option>
      <option value="open_risk">open_risk (Yellow)</option>
      <option value="all_risky">all_risky (Red max)</option>
      <option value="arp_spoof">arp_spoof (Red ARP)</option>
      <option value="hijacked">hijacked DNS (Red)</option>
    </select>
    <button class="primary" onclick="doScan()">🔍 Scan Now</button>
    <button onclick="doActive()">⚡ Active Check (5s)</button>
  </div>
</div>

<div class="layout">
  <!-- LEFT: AP LIST -->
  <div class="card">
    <h3>📡 Nearby Networks <span id="apcount" class="badge" style="margin-left:auto">0 APs</span></h3>
    <div id="aplist" class="ap-list"></div>
    <div class="foot">
      <span id="footmode">Mode: mock</span>
      <span>Built with CustomTkinter logic • Flask preview</span>
    </div>
  </div>

  <!-- RIGHT: SHIELD + WHY -->
  <div style="display:flex;flex-direction:column;gap:16px">
    <div class="card">
      <h3>🛡️ Threat Level Shield</h3>
      <div class="shield">
        <div id="orb" class="orb green">🛡️</div>
        <div id="level" class="level" style="color:var(--green)">SAFE</div>
        <div id="subtitle" class="sub">No threats detected</div>
        <div id="score" class="score">Suspicion: 0/100</div>
      </div>
      <div class="kvs">
        <div class="kv"><b>Gateway</b><div id="kv_gateway">—</div></div>
        <div class="kv"><b>DNS Canary</b><div id="kv_dns">—</div></div>
        <div class="kv"><b>Graph</b><div id="kv_graph">—</div></div>
        <div class="kv"><b>Findings</b><div id="kv_findings">—</div></div>
      </div>
    </div>

    <div class="card">
      <h3>💡 Why am I unsafe? <span class="badge">plain English</span></h3>
      <div id="explain" class="explain"></div>
      <div class="foot"><span>Tips update after each scan</span><span id="dur"></span></div>
    </div>
  </div>
</div>

<div class="top" style="position:relative;border-top:1px solid var(--border);border-bottom:none;margin-top:10px">
  <div style="font-size:13px;color:var(--muted)">
    <b>How to demo:</b> Mock = reliable evil twin (no Wi-Fi needed). Live = real scan via OS. Try <code>evil_twin → normal → all_risky</code> to see Green→Red.
    <br/>CLI also works: <code>python main.py --cli --mock --scenario evil_twin</code> • Tests: <code>pytest -q</code> → 12 passed
  </div>
  <div class="badge">Docs: ARCHITECTURE • DATA_FLOW • ETHICS • DEMO_SCRIPT</div>
</div>

<script>
let lastData=null;
async function doScan(){
  const mode=document.getElementById('mode').value;
  const scenario=document.getElementById('scenario').value;
  document.getElementById('footmode').textContent = `Scanning ${mode} ${scenario}...`;
  const res=await fetch(`/api/scan?mode=${mode}&scenario=${scenario}`);
  const data=await res.json();
  lastData=data;
  render(data);
}
async function doActive(){
  const mode=document.getElementById('mode').value;
  const scenario=document.getElementById('scenario').value;
  document.getElementById('footmode').textContent = `Active check 5s...`;
  const res=await fetch(`/api/active?mode=${mode}&scenario=${scenario}`);
  const data=await res.json();
  // merge active into lastData for display
  if(lastData){ lastData.active=data; render(lastData); }
  else render({active:data, threat:"green"});
}
function signalBars(dbm){
  if(dbm>=-50) return "▂▃▅▆█";
  if(dbm>=-67) return "▂▃▅▆ ";
  if(dbm>=-80) return "▂▃▅  ";
  return "▂    ";
}
function secIcon(enc){
  const m={WPA3:"🔒",WPA2:"🔒",WPA:"🔓","WPA-TKIP":"⚠️",WEP:"🔓",Open:"⚠️",Unknown:"❓"};
  return m[enc]||"❓";
}
function render(d){
  // shield
  const orb=document.getElementById('orb'), level=document.getElementById('level'), sub=document.getElementById('subtitle'), score=document.getElementById('score');
  const lvl=d.threat||"green";
  const map={green:{c:"green",t:"🛡️",label:"SAFE",col:"var(--green)"}, yellow:{c:"yellow",t:"⚠️",label:"CAUTION",col:"var(--yellow)"}, red:{c:"red",t:"🚨",label:"DANGER",col:"var(--red)"}};
  const m=map[lvl]||map.green;
  orb.className=`orb ${m.c}`; orb.textContent=m.t; level.textContent=m.label; level.style.color=m.col;
  sub.textContent=d.subtitle|| (lvl==="green"?"No threats detected":lvl==="yellow"?"Weak or unencrypted network":"Active attack suspected!");
  score.textContent=`Suspicion: ${d.evil_score||0}/100  •  ${d.networks?d.networks.length:0} APs`;

  // AP list
  const list=document.getElementById('aplist'); list.innerHTML="";
  document.getElementById('apcount').textContent=`${d.networks?d.networks.length:0} APs`;
  if(!d.networks||!d.networks.length){
    list.innerHTML=`<div style="padding:20px;color:var(--muted)">No networks. Use Mock mode for demo or check Wi-Fi adapter.</div>`;
  } else {
    const flagged=new Set(d.flagged_bssids||[]);
    d.networks.forEach(n=>{
      const div=document.createElement('div'); div.className='ap';
      if(flagged.has(n.bssid)) div.style.background='var(--redbg)';
      div.innerHTML=`
        <div class="ap-top">
          <div class="ssid">${secIcon(n.enc)} ${n.ssid} ${flagged.has(n.bssid)?'<span class="flag">⚠️ FLAGGED</span>':''}</div>
          <div class="sig">${signalBars(n.signal_dbm)} ${n.signal_dbm} dBm</div>
        </div>
        <div class="meta">${n.bssid} • ${n.vendor} • Ch${n.channel} • ${n.frequency} MHz</div>
        <div class="pills">
          <span class="pill ${n.enc}">${n.enc}</span>
          <span class="badge">BSSID ${n.bssid}</span>
          ${n.extra && n.extra.note ? `<span class="badge">${n.extra.note}</span>` : ``}
        </div>
      `;
      list.appendChild(div);
    });
  }

  // explain
  const ex=document.getElementById('explain'); ex.innerHTML="";
  const lines=d.explanations||[];
  if(!lines.length) ex.innerHTML=`<div class="reason green">All checks passed — you're on a safe network!</div>`;
  else lines.forEach(l=>{
    const div=document.createElement('div');
    const cls = l.toLowerCase().includes("hijack")||l.toLowerCase().includes("spoof")||l.includes("FLAGGED")|| l.includes("DANGER") ? "red" : l.includes("CAUTION")||l.includes("Open")||l.includes("WEP") ? "yellow":"green";
    div.className=`reason ${cls}`; div.textContent=l; ex.appendChild(div);
  });

  // kvs
  document.getElementById('kv_gateway').textContent = d.active ? `${d.active.arp.gateway_ip} → ${d.active.arp.gateway_mac||'unknown'} (${d.active.arp.vendor||''})` : (d.gateway||"— click Active Check");
  document.getElementById('kv_dns').textContent = d.active ? d.active.dns.summary : (d.dns_summary||"— click Active Check");
  document.getElementById('kv_graph').textContent = d.graph ? `${d.graph.suspicious_pairs} suspicious edges, density ${d.graph.density?d.graph.density.toFixed(2):0}, most connected ${d.graph.most_connected?d.graph.most_connected.bssid:"—"}` : "—";
  document.getElementById('kv_findings').textContent = `${d.findings?d.findings.length:0} risks • evil score ${d.evil_score||0}/100`;
  document.getElementById('footmode').textContent = `Mode: ${d.mode} ${d.scenario||""} • ${new Date().toLocaleTimeString()}`;
  document.getElementById('dur').textContent = d.active?`Active ${d.active.duration_sec}s`:"";
}
doScan();
</script>
</body>
</html>
"""

def build_payload(mode, scenario):
    # choose scanner
    if mode == "live":
        nets, source = get_live_networks()
        if not nets:
            # fallback to mock for demo reliability
            scanner = MockScanner(scenario="evil_twin")
            nets = scanner.scan()
            source = f"live fallback → mock (no adapter: {source})"
            mode_label = "live→mock"
        else:
            mode_label = "live"
    else:
        scanner = MockScanner(scenario=scenario)
        nets = scanner.scan()
        source = f"mock:{scenario}"
        mode_label = "mock"

    # Module1
    findings = auditor.audit(nets)
    # Module2
    detector.history.clear()
    detector.update_history(nets)
    evil_results = detector.analyze(nets)
    evil_score = detector.global_suspicion_score(evil_results)

    # Threat level logic (same as desktop)
    level_m1 = auditor.overall_level(findings)
    if evil_score >= 60:
        threat = "red"
        subtitle = f"Evil Twin likely! Score {evil_score}/100"
    elif evil_score >= 30:
        threat = "yellow" if level_m1 != "red" else "red"
        subtitle = f"Suspicious network (score {evil_score}/100)"
    elif findings:
        threat = "yellow"
        subtitle = auditor.plain_summary(findings)
    else:
        threat = "green"
        subtitle = f"Scanned {len(nets)} networks — all secure"

    # highlights
    highlights = {}
    for r in evil_results:
        for b in r.related_bssids:
            highlights[b] = r.score
    for f in findings:
        if f.severity in ("critical","high"):
            highlights[f.network.bssid] = highlights.get(f.network.bssid, f.score)

    # explanations
    explanations = []
    for f in findings:
        explanations.append(f"[{f.network.ssid} — {f.network.bssid}] {f.message} (Encryption: {f.network.encryption}, Vendor: {f.network.vendor})")
    if evil_results:
        explanations.extend(detector.plain_explanations(evil_results))
        for r in evil_results:
            gi = r.graph_insights
            if gi.get("suspicious_pairs",0)>0:
                explanations.append(f"Network graph: {gi['suspicious_pairs']} suspicious SSID relationships, density {gi.get('density',0):.2f}. Most connected AP: {gi.get('most_connected')}")
    if not explanations:
        explanations = [f"Scanned {len(nets)} networks — no risks found. You're on a reasonably secure setup."]

    # serialize networks
    net_json = []
    for n in nets:
        net_json.append({"ssid": n.ssid,"bssid": n.bssid,"signal_dbm": n.signal_dbm,"channel": n.channel,"frequency": n.frequency,"enc": n.short_encryption(),"encryption": n.encryption,"vendor": n.vendor,"extra": n.extra})

    graph = evil_results[0].graph_insights if evil_results else {}

    return {
        "mode": mode_label if 'mode_label' in locals() else mode,
        "scenario": scenario,
        "source": source,
        "networks": net_json,
        "findings": [{"ssid": f.network.ssid,"bssid": f.network.bssid,"risk": f.risk,"severity": f.severity,"message": f.message,"score": f.score} for f in findings],
        "evil_results": [{"ssid": r.ssid,"score": r.score,"level": r.level,"reasons": [{"code": rr.code,"message": rr.message,"weight": rr.weight,"evidence": rr.evidence} for rr in r.reasons]} for r in evil_results],
        "evil_score": evil_score,
        "threat": threat,
        "subtitle": subtitle,
        "flagged_bssids": list(highlights.keys()),
        "explanations": explanations,
        "graph": graph,
        "gateway": "— run Active Check",
        "dns_summary": "— run Active Check"
    }

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/scan")
def api_scan():
    mode = request.args.get("mode","mock")
    scenario = request.args.get("scenario","evil_twin")
    data = build_payload(mode, scenario)
    return jsonify(data)

@app.route("/api/active")
def api_active():
    mode = request.args.get("mode","mock")
    scenario = request.args.get("scenario","evil_twin")
    # Always mock for deterministic preview unless live
    mock = (mode=="mock")
    # For live, still use mock_arp_spoof logic if scenario hints attack
    checker = ActiveFingerprint()
    # Map web scenario to active mock scenario
    active_scenario = scenario
    if scenario == "evil_twin": active_scenario = "arp_spoof"
    result = checker.run(mock=True if mock else False, mock_scenario=active_scenario)
    arp = result.arp
    dns = result.dns
    return jsonify({
        "duration_sec": result.duration_sec,
        "threat_level": result.threat_level,
        "overall_safe": result.overall_safe,
        "summary": result.summary,
        "plain_explanations": result.plain_explanations,
        "arp": {"gateway_ip": arp.gateway_ip, "gateway_mac": arp.gateway_mac, "vendor": arp.gateway_mac_vendor, "all_macs": arp.all_macs_for_gateway, "is_spoof": arp.is_spoof_suspected, "reasons": arp.reasons},
        "dns": {"summary": dns.summary, "is_hijack": dns.is_hijack_suspected, "results": [{"domain": r.domain,"system_ips": r.system_ips,"trusted_ips": r.trusted_ips,"is_hijack": r.is_hijack_suspected,"reasons": r.reasons} for r in dns.results]}
    })

@app.route("/api/cli")
def api_cli():
    """Text-mode scan for headless check"""
    scenario = request.args.get("scenario","evil_twin")
    scanner = MockScanner(scenario=scenario)
    nets = scanner.scan()
    return jsonify({"networks": [{"ssid": n.ssid,"bssid": n.bssid,"signal_dbm": n.signal_dbm,"channel": n.channel,"encryption": n.encryption,"vendor": n.vendor} for n in nets]})

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--host", default="0.0.0.0")
    args = p.parse_args()
    print(f"ShieldFi Web Dashboard on http://{args.host}:{args.port} (mock default)")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)

