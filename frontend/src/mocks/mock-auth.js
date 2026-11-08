/**
 * Mock Authentication Data & Handlers
 * Simulates user sessions, tokens, and refresh behavior for local dev and demo mode.
 */

export const MOCK_USER = {
  id: 'e96f947e-8556-427c-b633-fc480c51b7fe',
  email: 'analyst@trustlens.dev',
  display_name: 'Security Analyst',
  role: 'user',
  is_active: true,
  created_at: '2026-11-01T10:00:00Z',
};

export const MOCK_TOKENS = {
  access_token: 'mock_jwt_access_token_trustlens_analyst_2026',
  refresh_token: 'mock_jwt_refresh_token_trustlens_analyst_2026',
  token_type: 'bearer',
  expires_in: 900,
  csrf_token: 'mock_csrf_token_8d3840212fef403692df894a8f9f2571',
};

/**
 * Simulate login
 * @param {string} email 
 * @param {string} password 
 */
export async function mockLogin(email, password) {
  await new Promise((res) => setTimeout(res, 400));
  if (password === 'wrongpassword') {
    throw {
      error: {
        code: 'AUTHENTICATION_REQUIRED',
        message: 'Invalid credentials provided.',
        request_id: 'mock-req-auth-fail',
      },
    };
  }
  return {
    user: {
      ...MOCK_USER,
      email: email || MOCK_USER.email,
      display_name: email ? email.split('@')[0] : MOCK_USER.display_name,
    },
    tokens: { ...MOCK_TOKENS },
  };
}

/**
 * Simulate registration
 * @param {string} email 
 * @param {string} password 
 * @param {string} displayName 
 */
export async function mockRegister(email, password, displayName) {
  await new Promise((res) => setTimeout(res, 500));
  if (email === 'taken@example.com') {
    throw {
      error: {
        code: 'STATE_CONFLICT',
        message: 'A user account with this email address already exists.',
        request_id: 'mock-req-reg-conflict',
      },
    };
  }
  return {
    user: {
      id: 'usr-' + Date.now(),
      email,
      display_name: displayName || email.split('@')[0],
      role: 'user',
      is_active: true,
      created_at: new Date().toISOString(),
    },
    tokens: { ...MOCK_TOKENS },
  };
}

/**
 * Simulate token refresh
 */
export async function mockRefreshToken() {
  await new Promise((res) => setTimeout(res, 200));
  return {
    access_token: 'mock_refreshed_access_token_' + Date.now(),
    refresh_token: 'mock_refreshed_token_' + Date.now(),
    token_type: 'bearer',
    expires_in: 900,
    csrf_token: 'mock_csrf_refreshed_' + Date.now(),
  };
}
