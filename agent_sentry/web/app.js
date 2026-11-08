const form = document.querySelector('#connect');
const status = document.querySelector('#status');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const token = document.querySelector('#token').value;
  const get = async (path) => {
    const response = await fetch(path, {headers: {Authorization: `Bearer ${token}`}});
    if (!response.ok) throw new Error(`Ledger request failed (${response.status})`);
    return response.json();
  };
  status.textContent = 'Reading ledger…';
  try {
    const [sessions, integrity] = await Promise.all([get('/v1/sessions'), get('/v1/verify')]);
    // Paginate so the view does not silently omit decisions after the first API page.
    let after = 0;
    let decisions = [];
    while (true) {
      const page = await get(`/v1/events?after=${after}&limit=500`);
      if (!page.events.length) break;
      after = page.events.at(-1).seq;
      decisions.push(...page.events.filter((e) => e.kind === 'decision'));
      decisions = decisions.slice(-100);
    }
    document.querySelector('#sessions').textContent = sessions.sessions.length;
    document.querySelector('#calls').textContent = sessions.sessions.reduce((sum, s) => sum + s.calls, 0);
    document.querySelector('#units').textContent = sessions.sessions.reduce((sum, s) => sum + s.units, 0);
    document.querySelector('#integrity').textContent = integrity.valid ? 'VALID' : 'BROKEN';
    const body = document.querySelector('#events');
    body.replaceChildren();
    for (const e of decisions.reverse()) {
      const tr = document.createElement('tr');
      [e.seq, e.tool, e.allowed ? 'ALLOW' : 'DENY', e.reason, e.session.slice(0, 12)].forEach((value, i) => {
        const td = document.createElement('td');
        td.textContent = String(value);
        if (i === 2) td.className = e.allowed ? 'allow' : 'deny';
        tr.append(td);
      });
      body.append(tr);
    }
    document.querySelector('#count').textContent = `${decisions.length} decisions shown`;
    status.textContent = 'Ledger loaded. Connect again to refresh; data is a point-in-time view.';
  } catch (error) {
    status.textContent = error.message;
  }
});
