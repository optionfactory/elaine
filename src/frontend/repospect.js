import { Templates } from "ftl";
import { HttpClient } from "httpc";

class Spinner {
    constructor() {
        this.el = document.querySelector('loading-spinner');
    }
    hide() {
        this.el.setAttribute('hidden', '');
    }
    async show() {
        this.el.removeAttribute('hidden');
        const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
        await sleep(10);
    }
}

class InfiniteScroller {
    constructor(gridSelector, sentinelSelector, templateSelector, spinner, batchSize = 5) {
        this.grid = document.querySelector(gridSelector);
        this.sentinel = document.querySelector(sentinelSelector);
        this.template = Templates.fromSelector(templateSelector);
        this.batchSize = batchSize;
        this.spinner = spinner;
        this.iterator = null;
        this.isFetching = false;

        this.observer = new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting && this.iterator && !this.isFetching) {
                this.renderNextBatch();
            }
        }, { rootMargin: '1000px' });
    }

    async load(asyncIterator) {
        this.iterator = asyncIterator;
        this.grid.innerHTML = '';
        this.observer.disconnect();
        await this.spinner.show();
        try {
            await this.renderNextBatch();
        } finally {
            this.spinner.hide();
        }
        this.observer.observe(this.sentinel);
    }

    async renderNextBatch() {
        const iterator = this.iterator;
        this.isFetching = true;
        const batch = [];
        try {
            for (let i = 0; i < this.batchSize; i++) {
                const item = await iterator.next();
                if (item.done) break;
                batch.push(item.value);
            }

            if (iterator !== this.iterator) return;

            if (batch.length === 0 && this.grid.children.length === 0) {
                this.grid.innerHTML = '<error-box>No matching repositories found.</error-box>';
                this.observer.unobserve(this.sentinel);
            } else if (batch.length === 0) {
                this.observer.unobserve(this.sentinel);
            } else {
                this.template.withOverlay(batch).appendTo(this.grid);
            }
        } catch (e) {
            if (iterator !== this.iterator) return;
            this.grid.innerHTML = '<error-box>Failed to load data.</error-box>';
            this.observer.unobserve(this.sentinel);
        } finally {
            if (iterator === this.iterator) {
                this.isFetching = false;
            }
        }
    }
}

const authenticate = async () => {
    const configResponse = await fetch('/api/config');
    const config = await configResponse.json();


    if (!config.google_auth) {
        const http = HttpClient.builder().build();
        return { config, http };
    }
    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    const idTokenFromHash = hashParams.get('id_token');

    if (idTokenFromHash) {
        sessionStorage.setItem('google_token', idTokenFromHash);
        window.history.replaceState(null, null, window.location.pathname);
    }

    const storedToken = sessionStorage.getItem('google_token');
    const isTokenExpired = (() => {
        if (!storedToken) {
            return true;
        }
        try {
            const payload = JSON.parse(atob(storedToken.split('.')[1]));
            return (payload.exp * 1000) < (Date.now() + 60000);
        } catch {
            return true;
        }
    })();

    if (isTokenExpired) {
        sessionStorage.removeItem('google_token');
        const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        authUrl.searchParams.set('client_id', config.google_auth.client_id);
        authUrl.searchParams.set('redirect_uri', window.location.origin + window.location.pathname);
        authUrl.searchParams.set('response_type', 'id_token');
        authUrl.searchParams.set('scope', 'openid email profile');
        authUrl.searchParams.set('nonce', Math.random().toString(36).substring(2));
        if (config.google_auth.hosted_domain) {
            authUrl.searchParams.set('hd', config.google_auth.hosted_domain);
        }
        window.location.href = authUrl.toString();
        await new Promise(() => { });
        // unreachable
    }
    const http = HttpClient.builder()
        .withInterceptors({
            async intercept(url, request, chain) {
                request.headers.set('Authorization', `Bearer ${storedToken}`);
                return await chain.proceed(url, request);
            }
        })
        .withRedirectOnUnauthorized('/')
        .build();
    return { config, http };
}


async function* projects(http, filters, search) {
    let offset = 0;
    const limit = 50;
    while (true) {
        const data = await http.get(`/api/projects`)
            .param("filters", filters == '' ? null : filters)
            .param("search", search)
            .param("offset", offset)
            .param("limit", limit)
            .fetchJson();
        for (const item of data) {
            yield item;
        }

        if (data.length < limit) {
            break;
        }

        offset += limit;
    }
}



export { Spinner, InfiniteScroller, authenticate, projects }
