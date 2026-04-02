/* RFT — Main JavaScript */

// ── API Status Check ──────────────────────────────────────────────────────────
async function checkAPIStatus() {
  try {
    const s = await fetch('/api/settings').then(r => r.json());
    const dot = document.getElementById('api-dot');
    const label = document.getElementById('api-label');
    if (!dot) return;
    if (s.api_key_set) {
      dot.className = 'status-dot ok';
      label.textContent = 'AI: Ready';
    } else {
      dot.className = 'status-dot error';
      label.textContent = 'AI: No key';
    }
  } catch (e) {
    const dot = document.getElementById('api-dot');
    if (dot) dot.className = 'status-dot error';
  }
}

// Run on every page load
checkAPIStatus();
