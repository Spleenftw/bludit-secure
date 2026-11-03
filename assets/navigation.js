'use strict';
(() => {
  const data = document.getElementById('bs-security-navigation');
  if (!data) return;
  const config = JSON.parse(data.textContent);
  const account = new URL(config.account, document.baseURI).href;
  const logout = new URL(config.logout, document.baseURI).href;
  const href = link => new URL(link.getAttribute('href'), document.baseURI).href;
  const makeLink = () => {
    const link = document.createElement('a');
    link.href = account;
    link.className = 'nav-link';
    const icon = document.createElement('span');
    icon.className = 'fa fa-shield';
    icon.setAttribute('aria-hidden', 'true');
    link.append(icon, document.createTextNode('Security'));
    return link;
  };
  // Native themes hide plugin sidebar hooks from authors and mobile editors.
  for (const nav of document.querySelectorAll('.sidebar .nav, #navbarNav .navbar-nav')) {
    if (Array.from(nav.querySelectorAll('a[href]')).some(link => href(link) === account)) continue;
    const item = document.createElement('li');
    item.className = 'nav-item';
    item.appendChild(makeLink());
    const logoutItem = Array.from(nav.children).find(child => Array.from(child.querySelectorAll('a[href]')).some(link => href(link) === logout));
    nav.insertBefore(item, logoutItem || null);
  }
  if (config.ownProfile) {
    const section = document.querySelector('#security.tab-pane');
    if (!section || section.querySelector('[data-bs-security-profile]')) return;
    const box = document.createElement('div');
    box.className = 'mb-4';
    box.setAttribute('data-bs-security-profile', 'true');
    const description = document.createElement('p');
    description.textContent = 'Manage TOTP, passkeys, SSO and recovery codes for your account.';
    const link = document.createElement('a');
    link.href = account;
    link.className = 'btn btn-outline-primary';
    link.textContent = 'Manage authentication methods';
    box.append(description, link);
    section.prepend(box);
  }
})();
