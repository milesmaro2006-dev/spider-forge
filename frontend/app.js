async function startUnifiedScan() {
    const targetUrl = document.getElementById('target-url').value.trim();
    if (!targetUrl) {
        alert('Please specify a target URL');
        return;
    }

    const scanBtn = document.getElementById('scan-btn');
    const loadingDiv = document.getElementById('loading');
    const resultsDiv = document.getElementById('scan-results');
    const vulnDiv = document.getElementById('vulnerabilities');
    const countBadge = document.getElementById('findings-count');

    scanBtn.disabled = true;
    loadingDiv.style.display = 'block';
    resultsDiv.style.display = 'none';
    vulnDiv.innerHTML = '';

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: targetUrl })
        });

        const data = await response.json();
        loadingDiv.style.display = 'none';
        scanBtn.disabled = false;

        if (response.ok && data.status === 'success') {
            const findings = data.data.findings || [];
            resultsDiv.style.display = 'block';
            countBadge.innerText = `${findings.length} Issues`;

            if (findings.length === 0) {
                vulnDiv.innerHTML = '<p style="color:#9ece6a;">No vulnerabilities detected for tested payloads.</p>';
                return;
            }

            findings.forEach(vuln => {
                const card = document.createElement('div');
                card.className = `vulnerability-card ${vuln.severity || 'Low'}`;
                card.innerHTML = `
                    <h4>${vuln.type}</h4>
                    <p><strong>Severity:</strong> ${vuln.severity}</p>
                    <p><strong>Target / Parameter:</strong> ${vuln.param || 'N/A'}</p>
                    <p><strong>Payload:</strong> <code>${vuln.payload || 'N/A'}</code></p>
                    <p><strong>Evidence:</strong> ${vuln.evidence || 'N/A'}</p>
                `;
                vulnDiv.appendChild(card);
            });
        } else {
            alert('Scan execution failed.');
        }
    } catch (err) {
        loadingDiv.style.display = 'none';
        scanBtn.disabled = false;
        console.error('Scan Error:', err);
        alert('Could not contact the local SpiderForge engine.');
    }
}