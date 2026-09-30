BAND_THRESHOLDS = ((80, "CRITICAL"), (60, "HIGH"), (40, "MEDIUM"), (20, "LOW"), (0, "NORMAL"))

def risk_band(score):
    score = max(0, min(100, int(round(score))))
    for threshold, band in BAND_THRESHOLDS:
        if score >= threshold:
            return band
    return "NORMAL"

def calculate_risk(findings):
    score = min(100, sum(max(0.0, f["weight"]) for f in findings))
    domains = {}
    for finding in findings:
        domain = finding["domain"]
        domains[domain] = min(100, domains.get(domain, 0) + max(0.0, finding["weight"]))
    domain_rows = [{"name": name, "score": int(round(value))}
                   for name, value in sorted(domains.items(), key=lambda x: (-x[1], x[0]))]
    band = risk_band(score)
    if findings:
        top = sorted(findings, key=lambda x: x["weight"], reverse=True)[:3]
        reasons = ", ".join(f["title"] for f in top)
        summary = (f"{len(findings)} indicator(s) were identified. Calculated risk: "
                   f"{int(round(score))}/100 ({band}). Key indicators: {reasons}. "
                   "Indicators require contextual verification; they do not prove compromise.")
    else:
        summary = "No suspicious indicators were identified in the supplied evidence."
    return {"score": int(round(score)), "band": band, "domains": domain_rows, "summary": summary}
