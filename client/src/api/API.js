import { CONFIG } from '../config.js';


const ACCESS_TOKEN_KEY = 'accessToken';
function getAccessToken() {
    return localStorage.getItem(ACCESS_TOKEN_KEY);
}


export async function setAccessToken(jwt) {
    localStorage.setItem(ACCESS_TOKEN_KEY, jwt);
}


export async function clearAccessToken(jwt) {
    localStorage.removeItem(ACCESS_TOKEN_KEY, jwt);
}


function getAuthorizationHeader() {
    const accessToken = getAccessToken();
    if (accessToken != null) {
        return { 'Authorization': `Bearer ${accessToken}` };
    } else {
        return {};
    }
}


export function isAuthenticated() {
    const accessToken = getAccessToken();
    if (accessToken == null) {
        return false;
    }
    const dataB64 = accessToken.split('.')[1];
    const data = JSON.parse(atob(dataB64));
    const expiresAtMillis = data.expiresAt * 1000;
    return Date.now() < expiresAtMillis;
}


export class APIError extends Error {
    constructor(status, data) {
        super(`APIError, status=${status} data=${data instanceof Object ? JSON.stringify(data) : data}`);
        this.status = status;
        this.data = data;
    }
}


function json2queryString(obj) {
    const objStr = JSON.stringify(obj)
    return `?json=${encodeURIComponent(objStr)}`;
}


const DEFAULT_HEADERS = {
    'Content-Type': 'application/json'
};
async function fireRequest(method, path, data = {}, headers = {}) {
    path = path.replace('/', '');
    method = method.toLowerCase();
    var queryString, body;
    if (['post', 'put', 'patch'].includes(method)) {
        // Send data in request body
        body = JSON.stringify(data);
        queryString = '';
    } else {
        // Send data in query string
        body = undefined;
        queryString = json2queryString(data);
    }
    const res = await fetch(`${CONFIG.API_BASE_URL}/${path}` + queryString, {
        method,
        headers: {
            ...DEFAULT_HEADERS,
            ...headers,
            ...getAuthorizationHeader(),
        },
        body,
    });
    const resJson = await res.json();
    
    if (!res.ok) {
        throw new APIError(res.status, resJson);
    }

    if (resJson.token != null) {
        // Store the refreshed token
        setAccessToken(resJson.token);
    }
    return resJson.response;
}

export async function get(url, data = {}, headers = {}) {
    return fireRequest('get', url, data, headers);
}

export async function post(url, data = {}, headers = {}) {
    return fireRequest('post', url, data, headers);
}

export async function put(url, data = {}, headers = {}) {
    return fireRequest('put', url, data, headers);
}

export async function patch(url, data = {}, headers = {}) {
    return fireRequest('patch', url, data, headers);
}
