BAND_THRESHOLDS = ((80, "CRITICAL"), (60, "HIGH"), (40, "MEDIUM"), (20, "LOW"), (0, "NORMAL"))

def risk_band(score):
    score = max(0, min(100, int(round(score))))
    for threshold, band in BAND_THRESHOLDS:
        if score >= threshold:
            return band
    return "NORMAL"

def calculate_risk(findings):
    score = min(100, sum(f["weight"] for f in findings))
    domains = {}
    for finding in findings:
        domain = finding["domain"]
        domains[domain] = min(100, domains.get(domain, 0) + finding["weight"])
    domain_rows = [{"name": name, "score": int(round(value))}
                   for name, value in sorted(domains.items(), key=lambda x: (-x[1], x[0]))]
    band = risk_band(score)
    if findings:
        summary = (f"The assessment identified {len(findings)} security indicator(s). "
                   f"The calculated risk is {int(round(score))}/100 ({band}). "
                   "Review the evidence before taking any remediation action.")
    else:
        summary = "No suspicious indicators were identified in the supplied evidence."
    return {"score": int(round(score)), "band": band, "domains": domain_rows, "summary": summary}
