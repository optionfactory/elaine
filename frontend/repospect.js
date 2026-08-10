import { Templates } from "ftl";


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

        this.observer = new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting && this.iterator && !this.isFetching) {
                this.renderNextBatch();
            }
        }, { rootMargin: '1000px' });
    }

    async load(iterator) {
        this.iterator = iterator;
        this.grid.innerHTML = '';
        this.observer.observe(this.sentinel);
        await this.spinner.show();
        try {
            await this.renderNextBatch();
        } finally {
            this.spinner.hide();
        }
    }

    async renderNextBatch() {
        const batch = Array.from({ length: this.batchSize }, () => this.iterator.next()).filter(item => !item.done).map(item => item.value);
        if (batch.length === 0 && this.grid.children.length === 0) {
            this.grid.innerHTML = '<error-box>No matching repositories found.</error-box>';
            this.observer.unobserve(this.sentinel);
            return;
        }
        if (batch.length === 0) {
            this.observer.unobserve(this.sentinel);
            return;
        }
        this.template.withOverlay(batch).appendTo(this.grid);
    }
}

export {Spinner, InfiniteScroller}