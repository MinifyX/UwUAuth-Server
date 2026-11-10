import '@uwusuite/design/plain.css';
import { useAppearance, useTypeScale } from '@uwusuite/design';
import React from 'react';
import ReactDOM from 'react-dom/client';
import { AdminApp } from './admin/AdminApp';
import { useLook } from './lib/appearance';
import { App } from './portal/App';
import './styles/app.css';
import './styles/pages.css';

const root = document.getElementById('root');
if (!root) throw new Error('#root missing from index.html');

// One app, two places: sign-in and the portal at `/`, the admin portal at `/admin`.
const admin = location.pathname.replace(/\/+$/, '') === '/admin';

/** Keeps <html> on the look the system asks for, unless the profile picked one for this browser. */
function Root() {
  const look = useLook();
  useAppearance(look);
  useTypeScale({ textSize: look.textSize });
  return admin ? <AdminApp /> : <App />;
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
);
