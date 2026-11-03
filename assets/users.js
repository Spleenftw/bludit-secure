'use strict';
(() => {
  const data = document.getElementById('bs-sso-users');
  if (!data) return;
  const records = new Map(JSON.parse(data.textContent).map(record => [new URL(record.url, document.baseURI).href, record]));
  const tables = new Set();
  for (const row of document.querySelectorAll('table tbody tr')) {
    const link = row.querySelector('td a[href]');
    const record = link && records.get(new URL(link.getAttribute('href'), document.baseURI).href);
    const table = row.closest('table');
    if (!record || !table || row.dataset.bsSso) continue;
    row.dataset.bsSso = 'true';
    tables.add(table);
    const status = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = record.linked ? 'badge badge-success' : 'badge badge-secondary';
    badge.textContent = record.linked ? 'Linked' : 'Not linked';
    status.appendChild(badge);
    if (record.linked) {
      const provider = document.createElement('div');
      provider.className = 'small text-muted';
      provider.textContent = record.provider;
      status.appendChild(provider);
    }
    const username = document.createElement('td');
    username.textContent = record.linked ? (record.username || (record.needsRefresh ? 'Sign in with SSO to refresh' : 'Not provided')) : '—';
    const email = document.createElement('td');
    email.textContent = record.linked ? (record.email || (record.needsRefresh ? 'Sign in with SSO to refresh' : 'Not provided')) : '—';
    if (record.email && !record.emailVerified) {
      const note = document.createElement('div');
      note.className = 'small text-muted';
      note.textContent = 'Not verified by provider';
      email.appendChild(note);
    }
    row.append(status, username, email);
  }
  for (const table of tables) {
    const header = table.querySelector('thead tr');
    if (!header || header.dataset.bsSso) continue;
    header.dataset.bsSso = 'true';
    for (const title of ['SSO', 'SSO username', 'SSO email']) {
      const cell = document.createElement('th');
      cell.className = 'border-bottom-0';
      cell.scope = 'col';
      cell.textContent = title;
      header.appendChild(cell);
    }
    if (!table.parentElement.classList.contains('table-responsive')) {
      const wrapper = document.createElement('div');
      wrapper.className = 'table-responsive';
      table.parentNode.insertBefore(wrapper, table);
      wrapper.appendChild(table);
    }
  }
})();
