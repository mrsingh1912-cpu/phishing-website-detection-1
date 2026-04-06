
document.getElementById('analyzeBtn').addEventListener('click', async () => {
  const resultBox = document.getElementById('result');
  resultBox.textContent = 'Reading current tab...';
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    resultBox.textContent = 'Could not read the current URL.';
    return;
  }
  resultBox.textContent = 'Sending URL to local detector...';
  try {
    const res = await fetch('http://127.0.0.1:5000/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url })
    });
    const data = await res.json();
    resultBox.innerHTML = `<b>Prediction:</b> ${data.prediction}<br><b>Risk:</b> ${data.risk_level}<br><b>Score:</b> ${data.risk_score}/100`;
  } catch (err) {
    resultBox.textContent = 'Could not reach local Flask app. Start python3 app.py first.';
  }
});
