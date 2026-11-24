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
        }, { rootMargin: `0px 0px ${window.innerHeight}px 0px` });
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
    const response = await fetch('/api/config');
    if (response.status === 401) {
        window.location.href = '/login';
        await new Promise(() => { });
    }
    const config = await response.json();
    if (config.email) {
        const signOut = document.createElement('a');
        signOut.className = 'sign-out';
        signOut.href = '/logout';
        signOut.title = `Sign out ${config.email}`;
        signOut.setAttribute('aria-label', 'Sign out');
        signOut.innerHTML = '<svg aria-hidden="true"><use href="icons.svg#icon-sign-out"></use></svg>';
        document.querySelector('body > header > nav').after(signOut);
    }
    const http = HttpClient.builder().withRedirectOnUnauthorized('/login').build();
    return { config, http };
}


async function* projects(http, filters, search) {
    let offset = 0;
    const limit = 50;
    while (true) {
        const data = await http.get(`/api/projects`)
            .param("filter", ...filters)
            .param("search", search)
            .param("offset", offset)
            .param("limit", limit)
            .fetchJson();
        for (const item of data) {
            yield withDerivedFields(item);
        }

        if (data.length < limit) {
            break;
        }

        offset += limit;
    }
}

/// Adds convenience fields computed from the raw API payload.
function withDerivedFields(p) {
    const failed_checks = Object.values(p.health ?? {})
        .reduce((sum, checks) => sum + Object.values(checks).filter(s => s === 'failed').length, 0);
    return { ...p, failed_checks };
}



/// Fullscreen modal dialog with a title, close button, and content area.
class Dialog {
    constructor() {
        const host = document.createElement('div');
        host.innerHTML = `
            <dialog>
                <header>
                    <h1></h1>
                    <button type="button" aria-label="Close">&times;</button>
                </header>
                <div></div>
            </dialog>
        `;
        const root = host.querySelector('dialog');
        this.el = root;
        this.titleEl = root.querySelector('header h1');
        this.contentEl = root.querySelector('div');
        root.querySelector('header button').addEventListener('click', () => this.close());
        document.body.appendChild(root);
    }

    open(title, content) {
        if (this.titleEl) this.titleEl.textContent = title ?? '';
        if (typeof content === 'string') {
            this.contentEl.textContent = content;
        } else if (content instanceof Node) {
            this.contentEl.replaceChildren(content);
        }
        this.el.showModal();
    }

    close() {
        this.el.close();
    }

    onClose(callback) {
        this.el.addEventListener('close', callback);
    }
}

/// Highlights the section nav link matching the section currently in view.
function setupNavSpy() {
    const navLinks = document.querySelectorAll('header > nav:nth-of-type(2) a');
    if (navLinks.length === 0) return;
    const sections = [...navLinks].map(a => document.querySelector(a.hash));
    const spy = new IntersectionObserver(entries => {
        for (const entry of entries) {
            if (!entry.isIntersecting) continue;
            navLinks.forEach(a => a.classList.toggle('active', a.hash === `#${entry.target.id}`));
        }
    }, { rootMargin: '-10% 0px -80% 0px' });
    sections.forEach(s => s && spy.observe(s));
}

/// The page of a repository, and of a steward as their manifests write them.
const repositoryHref = name => `repository.html#${encodeURIComponent(name)}`;
const stewardHref = steward => `steward.html#${encodeURIComponent(steward)}`;

/// "3 months ago", "just now": for tables; `exactTime` goes in the title, for the hover.
function relativeTime(iso) {
    if (!iso) return 'never';
    const seconds = (Date.now() - new Date(iso).getTime()) / 1000;
    const units = [['year', 31557600], ['month', 2629800], ['day', 86400], ['hour', 3600], ['minute', 60]];
    for (const [unit, size] of units) {
        const count = Math.floor(seconds / size);
        if (count >= 1) return `${count} ${unit}${count > 1 ? 's' : ''} ago`;
    }
    return 'just now';
}

function exactTime(iso) {
    return iso ? new Date(iso).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : '';
}

export { Spinner, InfiniteScroller, authenticate, projects, Dialog, setupNavSpy, repositoryHref, stewardHref, relativeTime, exactTime }
