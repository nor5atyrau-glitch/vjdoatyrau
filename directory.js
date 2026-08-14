// Netlify Function: serves and persists the phone directory using Netlify Blobs.
// Endpoints (all via /api/directory, routed by ?action=... and HTTP method):
//   GET  /api/directory                -> { data, hasPassword }         (public read)
//   POST /api/directory?action=login   -> { ok: true|false }            body: { password }
//   POST /api/directory?action=save    -> { ok: true }                  header: x-admin-password, body: full DATA object
//   POST /api/directory?action=password-> { ok: true }                  header: x-admin-password (current), body: { newPassword }
//
// The admin password is never sent to the browser — it is only compared
// server-side, either against the value stored in Blobs or against the
// ADMIN_PASSWORD environment variable (fallback default: atyrau2026).

const { getStore } = require('@netlify/blobs');

const DEFAULT_PASSWORD = 'atyrau2026';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, x-admin-password',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Content-Type': 'application/json; charset=utf-8'
};

function json(statusCode, body) {
  return { statusCode, headers: CORS_HEADERS, body: JSON.stringify(body) };
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS_HEADERS, body: '' };
  }

  const dataStore = getStore('vzhdo-directory-data');
  const authStore = getStore('vzhdo-directory-auth');
  const action = (event.queryStringParameters && event.queryStringParameters.action) || '';

  async function getCurrentPassword() {
    const stored = await authStore.get('password');
    return stored || process.env.ADMIN_PASSWORD || DEFAULT_PASSWORD;
  }

  try {
    if (event.httpMethod === 'GET') {
      const data = await dataStore.get('data', { type: 'json' });
      return json(200, { data: data || null });
    }

    if (event.httpMethod === 'POST' && action === 'login') {
      const body = JSON.parse(event.body || '{}');
      const current = await getCurrentPassword();
      return json(200, { ok: body.password === current });
    }

    if (event.httpMethod === 'POST' && action === 'save') {
      const providedPassword = event.headers['x-admin-password'] || '';
      const current = await getCurrentPassword();
      if (providedPassword !== current) {
        return json(401, { ok: false, error: 'Неверный пароль администратора' });
      }
      let payload;
      try {
        payload = JSON.parse(event.body || '{}');
      } catch (e) {
        return json(400, { ok: false, error: 'Некорректный JSON' });
      }
      if (!payload || !Array.isArray(payload.groups)) {
        return json(400, { ok: false, error: 'Ожидался объект со списком groups' });
      }
      await dataStore.setJSON('data', payload);
      return json(200, { ok: true });
    }

    if (event.httpMethod === 'POST' && action === 'password') {
      const providedPassword = event.headers['x-admin-password'] || '';
      const current = await getCurrentPassword();
      if (providedPassword !== current) {
        return json(401, { ok: false, error: 'Неверный текущий пароль' });
      }
      const body = JSON.parse(event.body || '{}');
      const newPassword = (body.newPassword || '').trim();
      if (!newPassword) {
        return json(400, { ok: false, error: 'Пустой новый пароль' });
      }
      await authStore.set('password', newPassword);
      return json(200, { ok: true });
    }

    return json(405, { ok: false, error: 'Метод не поддерживается' });
  } catch (err) {
    console.error('directory function error:', err);
    return json(500, { ok: false, error: 'Внутренняя ошибка сервера' });
  }
};
