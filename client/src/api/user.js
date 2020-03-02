import { get } from './API.js';

export async function me() {
    return get('/user/me');
}
