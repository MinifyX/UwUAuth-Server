import '@fontsource-variable/manrope';
import React from 'react';
import ReactDOM from 'react-dom/client';
import { AdminApp } from './admin/AdminApp';
import './components/nyu/nyu.css';
import { applyTheme } from './lib/theme';
import { App } from './portal/App';
import './styles/tokens.css';
import './styles/app.css';
import './styles/pages.css';

// Light or dark as the system says, unless the profile picked one for this browser.
applyTheme();

const root = document.getElementById('root');
if (!root) throw new Error('#root missing from index.html');

// One app, two places: sign-in and the portal at `/`, the admin portal at `/admin`.
const admin = location.pathname.replace(/\/+$/, '') === '/admin';

ReactDOM.createRoot(root).render(
  <React.StrictMode>{admin ? <AdminApp /> : <App />}</React.StrictMode>,
);
