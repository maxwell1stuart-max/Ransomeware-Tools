// APT — main.js

// API key status check
async function checkApiStatus() {
  try {
    const s = await fetch('/api/settings').then(r => r.json());
    const dot = document.getElementById('api-dot');
    const label = document.getElementById('api-label');
    if (dot && label) {
      if (s.api_key_set) {
        dot.style.background = 'var(--accent-green)';
        label.textContent = 'AI: Active';
      } else {
        dot.style.background = 'var(--accent-yellow)';
        label.textContent = 'AI: No key';
      }
    }
  } catch (e) {}
}

document.addEventListener('DOMContentLoaded', checkApiStatus);
