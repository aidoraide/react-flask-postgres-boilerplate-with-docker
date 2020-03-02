import { get, post, put, patch, clearAccessToken, setAccessToken } from './API.js';

export async function login(email, password) {
    const resp = await post('/auth/login', { email, password });
    setAccessToken(resp.token);
    return resp;
}

export async function signup(email, password) {
    const resp = await post('/auth/signup', { email, password });
    setAccessToken(resp.token);
    return resp;
}

export async function logoutEverywhere() {
    const resp = await post('/auth/logout_everywhere');
    clearAccessToken();
    return resp;
}

export async function confirmEmail(confirmationSecret, userID, email) {
    return post(
        '/auth/confirm_email',
        {
            confirmation_secret: confirmationSecret,
            user_id: userID,
            email,
        },
    );
}

export async function initiatePasswordReset(email) {
    return post(
        '/auth/initiate_password_request',
        { email },
    );
}

export async function resetPassword(password, secretCode, passwordResetRequestID) {
    return post(
        '/auth/reset_password',
        {
            password,
            secret_code: secretCode,
            password_reset_request_id: passwordResetRequestID,
        },
    );
}
