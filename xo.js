var xover = {};
var xo = xover;
xover.app = {};
xover.debug = {};
xover.browser = {};
xover.cache = {};
xover.cryptography = {};
xover.cryptography.generateUUID = function () {//from https://stackoverflow.com/questions/105034/how-to-create-a-guid-uuid
    // Public Domain/MIT -- For https we can use Crypto web api
    var d = new Date().getTime();//Timestamp
    var d2 = ((typeof performance !== 'undefined') && performance.now && (performance.now() * 1000)) || 0;//Time in microseconds since page-load or 0 if unsupported
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16;//random number between 0 and 16
        if (d > 0) {//Use timestamp until depleted
            r = (d + r) % 16 | 0;
            d = Math.floor(d / 16);
        } else {//Use microseconds since page-load if supported
            r = (d2 + r) % 16 | 0;
            d2 = Math.floor(d2 / 16);
        }
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}
xover.cryptography.decodeJwt = function (token) {//from https://stackoverflow.com/questions/38552003/how-to-decode-jwt-token-in-javascript-without-using-a-library
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
}
xover.cryptography.encodeBase64 = function (str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function (match, p1) {
        return String.fromCharCode('0x' + p1);
    }));
}
xover.cryptography.encodeMD5 = function (str) {
    /*
     * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
     * Digest Algorithm, as defined in RFC 1321.
     * Copyright (C) Paul Johnston 1999 - 2000.
     * Updated by Greg Holt 2000 - 2001.
     * See http://pajhome.org.uk/site/legal.html for details.
     */

    /*
     * Convert a 32-bit number to a hex string with ls-byte first
     */
    var hex_chr = "0123456789abcdef";
    function rhex(num) {
        str = "";
        for (let j = 0; j <= 3; j++)
            str += hex_chr.charAt((num >> (j * 8 + 4)) & 0x0F) +
                hex_chr.charAt((num >> (j * 8)) & 0x0F);
        return str;
    }

    /*
     * Convert a string to a sequence of 16-word blocks, stored as an array.
     * Append padding bits and the length, as described in the MD5 standard.
     */
    function str2blks_MD5(str) {
        let i;
        nblk = ((str.length + 8) >> 6) + 1;
        blks = new Array(nblk * 16);
        for (i = 0; i < nblk * 16; i++) blks[i] = 0;
        for (i = 0; i < str.length; i++)
            blks[i >> 2] |= str.charCodeAt(i) << ((i % 4) * 8);
        blks[i >> 2] |= 0x80 << ((i % 4) * 8);
        blks[nblk * 16 - 2] = str.length * 8;
        return blks;
    }

    /*
     * Add integers, wrapping at 2^32. This uses 16-bit operations internally 
     * to work around bugs in some JS interpreters.
     */
    function add(x, y) {
        var lsw = (x & 0xFFFF) + (y & 0xFFFF);
        var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }

    /*
     * Bitwise rotate a 32-bit number to the left
     */
    function rol(num, cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    }

    /*
     * These functions implement the basic operation for each round of the
     * algorithm.
     */
    function cmn(q, a, b, x, s, t) {
        return add(rol(add(add(a, q), add(x, t)), s), b);
    }
    function ff(a, b, c, d, x, s, t) {
        return cmn((b & c) | ((~b) & d), a, b, x, s, t);
    }
    function gg(a, b, c, d, x, s, t) {
        return cmn((b & d) | (c & (~d)), a, b, x, s, t);
    }
    function hh(a, b, c, d, x, s, t) {
        return cmn(b ^ c ^ d, a, b, x, s, t);
    }
    function ii(a, b, c, d, x, s, t) {
        return cmn(c ^ (b | (~d)), a, b, x, s, t);
    }

    x = str2blks_MD5(str);
    a = 1732584193;
    b = -271733879;
    c = -1732584194;
    d = 271733878;

    for (let i = 0; i < x.length; i += 16) {
        olda = a;
        oldb = b;
        oldc = c;
        oldd = d;

        a = ff(a, b, c, d, x[i + 0], 7, -680876936);
        d = ff(d, a, b, c, x[i + 1], 12, -389564586);
        c = ff(c, d, a, b, x[i + 2], 17, 606105819);
        b = ff(b, c, d, a, x[i + 3], 22, -1044525330);
        a = ff(a, b, c, d, x[i + 4], 7, -176418897);
        d = ff(d, a, b, c, x[i + 5], 12, 1200080426);
        c = ff(c, d, a, b, x[i + 6], 17, -1473231341);
        b = ff(b, c, d, a, x[i + 7], 22, -45705983);
        a = ff(a, b, c, d, x[i + 8], 7, 1770035416);
        d = ff(d, a, b, c, x[i + 9], 12, -1958414417);
        c = ff(c, d, a, b, x[i + 10], 17, -42063);
        b = ff(b, c, d, a, x[i + 11], 22, -1990404162);
        a = ff(a, b, c, d, x[i + 12], 7, 1804603682);
        d = ff(d, a, b, c, x[i + 13], 12, -40341101);
        c = ff(c, d, a, b, x[i + 14], 17, -1502002290);
        b = ff(b, c, d, a, x[i + 15], 22, 1236535329);

        a = gg(a, b, c, d, x[i + 1], 5, -165796510);
        d = gg(d, a, b, c, x[i + 6], 9, -1069501632);
        c = gg(c, d, a, b, x[i + 11], 14, 643717713);
        b = gg(b, c, d, a, x[i + 0], 20, -373897302);
        a = gg(a, b, c, d, x[i + 5], 5, -701558691);
        d = gg(d, a, b, c, x[i + 10], 9, 38016083);
        c = gg(c, d, a, b, x[i + 15], 14, -660478335);
        b = gg(b, c, d, a, x[i + 4], 20, -405537848);
        a = gg(a, b, c, d, x[i + 9], 5, 568446438);
        d = gg(d, a, b, c, x[i + 14], 9, -1019803690);
        c = gg(c, d, a, b, x[i + 3], 14, -187363961);
        b = gg(b, c, d, a, x[i + 8], 20, 1163531501);
        a = gg(a, b, c, d, x[i + 13], 5, -1444681467);
        d = gg(d, a, b, c, x[i + 2], 9, -51403784);
        c = gg(c, d, a, b, x[i + 7], 14, 1735328473);
        b = gg(b, c, d, a, x[i + 12], 20, -1926607734);

        a = hh(a, b, c, d, x[i + 5], 4, -378558);
        d = hh(d, a, b, c, x[i + 8], 11, -2022574463);
        c = hh(c, d, a, b, x[i + 11], 16, 1839030562);
        b = hh(b, c, d, a, x[i + 14], 23, -35309556);
        a = hh(a, b, c, d, x[i + 1], 4, -1530992060);
        d = hh(d, a, b, c, x[i + 4], 11, 1272893353);
        c = hh(c, d, a, b, x[i + 7], 16, -155497632);
        b = hh(b, c, d, a, x[i + 10], 23, -1094730640);
        a = hh(a, b, c, d, x[i + 13], 4, 681279174);
        d = hh(d, a, b, c, x[i + 0], 11, -358537222);
        c = hh(c, d, a, b, x[i + 3], 16, -722521979);
        b = hh(b, c, d, a, x[i + 6], 23, 76029189);
        a = hh(a, b, c, d, x[i + 9], 4, -640364487);
        d = hh(d, a, b, c, x[i + 12], 11, -421815835);
        c = hh(c, d, a, b, x[i + 15], 16, 530742520);
        b = hh(b, c, d, a, x[i + 2], 23, -995338651);

        a = ii(a, b, c, d, x[i + 0], 6, -198630844);
        d = ii(d, a, b, c, x[i + 7], 10, 1126891415);
        c = ii(c, d, a, b, x[i + 14], 15, -1416354905);
        b = ii(b, c, d, a, x[i + 5], 21, -57434055);
        a = ii(a, b, c, d, x[i + 12], 6, 1700485571);
        d = ii(d, a, b, c, x[i + 3], 10, -1894986606);
        c = ii(c, d, a, b, x[i + 10], 15, -1051523);
        b = ii(b, c, d, a, x[i + 1], 21, -2054922799);
        a = ii(a, b, c, d, x[i + 8], 6, 1873313359);
        d = ii(d, a, b, c, x[i + 15], 10, -30611744);
        c = ii(c, d, a, b, x[i + 6], 15, -1560198380);
        b = ii(b, c, d, a, x[i + 13], 21, 1309151649);
        a = ii(a, b, c, d, x[i + 4], 6, -145523070);
        d = ii(d, a, b, c, x[i + 11], 10, -1120210379);
        c = ii(c, d, a, b, x[i + 2], 15, 718787259);
        b = ii(b, c, d, a, x[i + 9], 21, -343485551);

        a = add(a, olda);
        b = add(b, oldb);
        c = add(c, oldc);
        d = add(d, oldd);
    }
    return rhex(a) + rhex(b) + rhex(c) + rhex(d);
}

Object.defineProperty(Array.prototype, 'coalesce',
    {
        value: function () {
            let args = this instanceof Array && this || arguments;
            for (let item of args) {
                if (item !== undefined && item !== null) {
                    return item;
                }
            }
            return;
        },
        writable: true, enumerable: false, configurable: false
    }
);

Object.defineProperty(Array.prototype, 'distinct',
    {
        value: function () {
            return [... new Set(this)];
        },
        writable: true, enumerable: false, configurable: false
    }
);

Object.defineProperty(Array.prototype, 'order',
    {
        value: function (direction = 'ASC') {
            return this.sort((a, b) => {
                const orderA = parseInt(a.value || a);
                const orderB = parseInt(b.value || b);
                return (direction || '').toUpperCase() == 'ASC' ? orderA - orderB : orderB - orderA;
            })
        },
        writable: true, enumerable: false, configurable: false
    }
);

xover.custom = {};
xover.data = {};
xover.stores = new Proxy({}, {
    get: function (self, key) {
        if (key in self) {
            return self[key];
        } else if (key[0] == '$') {
            return xover.stores[`#${key.split("$").pop()}`];
            //} else if (key[0] == '#' && xover.session[key]) {
            //    restored_document = xover.session[key];
            //    if ()
            //    //if (!(restored_document instanceof xover.Store) && restored_document instanceof XMLDocument) {
            //    //    self[key] = new xover.Store(restored_document, { tag: key });
            //    //}
            //    return self[key];
        } else if (key[0] == '#' /*&& key in xover.sources*/) {
            xover.stores[key] = new xover.Store(xover.sources[key], { tag: key });
            return xover.stores[key];
        } /*else if (key[0] == '#' && key in xover.sources.defaults) {
            let _store = key in xover.sources.defaults && new xover.Store(xover.sources.defaults[key], { tag: key });
            if (_store) {
                self[key] = _store;
            }
            return self[key];
        } else if (key !== key.toLowerCase()) {
            return xover.stores[key.toLowerCase()];
        } else {
            return;
        }*/
    },
    set: function (self, key, value) {
        let refresh;
        if (value && !(value instanceof xover.Store)) {
            if (value instanceof XMLDocument && value.stylesheets.length) {
                value = new xover.Store(value);
            } else {
                throw (new Error('Supplied store is not valid type'));
            }
        }
        //Object.defineProperty(value.document, 'store', {
        //    get: function () {
        //        return value
        //    }
        //})
        value.document.store = value;
        self[key] = value
        return self[key];
    },
    deleteProperty: function (self, key) {
        let exists = key in self
        let same = self[xover.site.seed] === self[key]
        sessionStorage.removeItem(key);
        xover.storehouse.remove('sources', key);

        if (exists) {
            delete self[key];
            delete xover.sources[key];
            if (same && xover.site.position > 1) {
                history.back();
            } /*else {
                xover.dom.refresh();
            }*/
        }
        return exists && !(key in self)
    }, has: function (self, key) {
        return key in self || key.toLowerCase() in self || key in xover.sources || key in (xover.manifest.server || {});
    }
});

xover.data.binding = {};
xover.data.binding["max_subscribers"] = 30;
xover.data.binding.sources = {};
xover.data.binding.requests = {};
xover.data.titles = {};
xover.storehouse = new Proxy({
    config: {
        'files': { keyPath: "uid" }
        , 'sources': { autoIncrement: true }
    }
}, {
    get: function (self, key) {
        if (key in self) {
            return self[key];
        }
        return self.open(key);
    }
});

Object.defineProperty(xover.storehouse, 'files', {
    get: async function () {
        let store = await xover.storehouse.open('files', { keyPath: "uid" });
        let _add = store.add;
        store.add = function (files) {
            let _url;
            let _cached_ids = [];

            for (let file of files) {
                _url = window.URL.createObjectURL(file);
                let record = {}
                record.uid = _url;
                record.id = _url.substring(_url.lastIndexOf('/') + 1);
                record.extension = file.name.substring(file.name.lastIndexOf('.') + 1);
                record.saveAs = record.id;/*`${record.id}.${record.extension}`;*/
                record.file = file;
                _add(record);
                _cached_ids.push(record);
            }
            return _cached_ids;
        }
        return store;
    }
});

Object.defineProperty(xover.storehouse, 'sources', {
    get: async function () {
        let store = await xover.storehouse.open('sources');
        let _add = store.add;
        store.add = function (source, name = '') {
            let record_key = name;
            let file = new File([source], record_key, {
                type: "application/xml",
            });
            _add(file, record_key);
        }
        let _put = store.put;
        store.put = function (source, name = '') {
            let record_key = name;
            let file = new File([source], record_key, {
                type: "application/xml",
            });
            _put(file, record_key);
        }
        let _get = store.get;
        store.get = async function (name = '') {
            let record_key = name;
            let record = await _get(record_key);
            let content = record && record.text && await record.text() || undefined;
            let document = content && xover.xml.createDocument(content) || undefined;
            if (document instanceof Document && record) {
                document.lastModifiedDate = record.lastModified;
            }
            return document;
        }
        return store;
    }
});

Object.defineProperties(xover.storehouse, {
    read: {
        value: async function (store_name, key) {
            let store;
            store = await this[store_name];
            return store.get(key);
        }
    },
    remove: {
        value: async function (store_name, key) {
            store = await this[store_name];
            return store.delete(key);
        }
    },
    write: {
        value: async function (store_name, key, value) {
            store = await this[store_name];
            //if (value instanceof Document) {
            //    value = value.toString();
            //}
            return store.put(value, key);
        }
    },
    open: {
        value: function (key, config = { autoIncrement: true }, method = 'readwrite') {
            return new Promise(async (resolve, reject) => {
                let stores = Object.fromEntries(Object.entries(Object.getOwnPropertyDescriptors(xover.storehouse)).filter(([prop, func]) => func["get"] || func["enumerable"]));
                //let storehouse = await indexedDB.stores().then(stores => stores.find(db => db.name == 'xover.storehouse'));
                let connection = indexedDB.open('xover.storehouse', 4);
                let handler = function (event) {
                    let store = event.target.result.transaction([key], method).objectStore(key);
                    store.add = function (...args) {
                        return new Promise((resolve, reject) => {
                            let request = IDBObjectStore.prototype.add.apply(store, args);

                            request.onerror = function (event) {
                                reject(request.result);
                            };

                            request.onsuccess = function (event) {
                                resolve(request.result);
                            };
                        });
                    }
                    store.get = function (...args) {
                        return new Promise((resolve, reject) => {
                            let request = IDBObjectStore.prototype.get.apply(store, args);

                            request.onerror = function (event) {
                                reject(request.result);
                            };

                            request.onsuccess = function (event) {
                                resolve(request.result);
                            };
                        });
                    }
                    store.put = function (...args) {
                        return new Promise((resolve, reject) => {
                            let request = IDBObjectStore.prototype.put.apply(store, args);

                            request.onerror = function (event) {
                                reject(request.result);
                            };

                            request.onsuccess = function (event) {
                                resolve(request.result);
                            };
                        });
                    }
                    store.delete = function (...args) {
                        return new Promise((resolve, reject) => {
                            let request = IDBObjectStore.prototype.delete.apply(store, args);

                            request.onerror = function (event) {
                                reject(request.result);
                            };

                            request.onsuccess = function (event) {
                                resolve(request.result);
                            };
                        });
                    }
                    store.openCursor = function (...args) {
                        return new Promise((resolve, reject) => {
                            let request = IDBObjectStore.prototype.openCursor.apply(store, args);
                            let records = []
                            request.onerror = function (event) {
                                reject(event.target.result);
                            };

                            request.onsuccess = async function (event) {
                                let cursor = event.target.result;
                                if (cursor) {
                                    records.push([cursor.key, store.get(cursor.key)])
                                    cursor.continue();
                                } else {
                                    resolve(records);
                                }
                            };
                        });
                    }
                    return store;
                }
                connection.onsuccess = function (event) { resolve(handler(event)) };
                connection.onerror = function (event) { reject(event) };
                connection.onupgradeneeded = function (event) {
                    let db = event.target.result;
                    Object.entries(Object.getOwnPropertyDescriptors(stores)).filter(([prop, description]) => description.value.get).map(([store_name]) => {
                        if (!Array.from(db.objectStoreNames).includes(store_name)) {
                            db.createObjectStore(store_name, xover.storehouse.config[store_name]);//autoIncrement: true
                        }
                    });
                };
            })
        }
    }
})

xover.dom = {};
xover.dom.history = [];
xover.dom.intervals = new Proxy({}, {
    get: function (self, key) {
        return self[key];
    },
    set: function (self, key, input) {
        self[key] = input;
        return self[key];
    },
    deleteProperty: function (self, key) {
        if (key in self) {
            window.clearInterval(self[key]);
            delete self[key];
        }
    }
})

xover.dom.controls = {};
xover.dom.refreshTitle = function (input) {
    let document_title = (input || document.title).match(/([^\(]+)(.*)/);
    let [, title, environment] = (document_title || [, "", ""]);
    document.title = title.replace(/\s+$/, '') + (` (${xover.session.store_id && xover.session.store_id != 'main' ? xover.session.store_id : 'v.'} ${xover.session.cache_name && xover.session.cache_name.split('_').pop() || ""})`).replace(/\((v\.)?\s+\)|\s+(?=\))/g, '');
}

xover.delay = function (ms) {
    return ms ? new Promise(resolve => setTimeout(resolve, ms)) : Promise.resolve();
}


xover.init = async function () {
    this.init.initializing = this.init.initializing || xover.delay(1).then(async () => {
        xover.modernize();
        if (history.state) delete history.state.active;
        for (let link of [...document.querySelectorAll('link[rel="xover-manifest"]')].filter(manifest => (manifest.getAttribute("href") || {}).indexOf('.manifest') != -1 || (manifest.getAttribute("href") || {}).indexOf('manifest.json') != -1)) {
            let url = xover.URL(link.getAttribute("href"));
            try {
                let manifest = await xover.fetch.json(url, { headers: { Accept: "*/*" } }).catch(e => console.log(e));
                manifest = new xo.Manifest(manifest);
                manifest.stylesheets = (manifest.stylesheets || []).map(el => new URL(el, url).href);
                xover.manifest.merge(manifest)
            } catch (e) {
                Promise.reject(e);
            }
        }
        Object.assign(xover.spaces, xover.manifest.spaces);
        let stylesheet_promises = []
        for (let source of xover.manifest.stylesheets.map(href => xover.sources[href])) {
            stylesheet_promises.push(source.fetch().catch(e => Promise.reject(e)));
        }
        await Promise.all(stylesheet_promises);
        await xover.stores.restore();
        xover.session.cache_name = typeof (caches) != 'undefined' && (await caches.keys()).find(cache => cache.match(new RegExp(`^${location.hostname}_`))) || "";
        xover.dom.refreshTitle();
        this.init.status = 'initialized';
        xover.site.sections.forEach(section => section.render());
        let active = xover.stores.active;
        active && active.render();
        xover.session.checkStatus();
        return Promise.resolve();
    }).catch(e => {
        return Promise.reject(e);
    }).finally(() => {
        this.init.initializing = undefined;
    });
    return this.init.initializing;
}

xover.initializeElementListeners = function (document = window.document) {
    const observer = new MutationObserver((mutationsList, observer) => {
        if (event && event.type == 'input') return;
        for (const mutation of mutationsList) {
            if (mutation.type === 'characterData') {
                // Handle text node changes here
                const changedTextNode = mutation.target;
                let scope = changedTextNode.scope;
                if (!scope) continue;
                scope.set(changedTextNode.nodeValue);
            }
        }
    });

    document.querySelectorAll('img').forEach(el => el.addEventListener('error', function () {
        if (event && (event.srcEvent || event).type == 'error') {
            window.top.dispatchEvent(new xover.listener.Event('error', { event: event }));
        }
    }));

    document.querySelectorAll('input,textarea').forEach(el => el.addEventListener('focus', function () {
        if (event && (event.srcEvent || event).type == 'focus') {
            window.top.dispatchEvent(new xover.listener.Event('focus', { event: event }));
        }
    }));

    document.querySelectorAll('textarea').forEach(el => el.addEventListener('mouseup', function () {
        //let el = event.srcElement;
        //let scope = el.scope;
        //if (scope instanceof Attr) {
        //    scope.parentNode.set(`height:${scope.localName}`, el.offsetHeight, { silent: true });
        //    scope.parentNode.set(`width:${scope.localName}`, el.offsetWidth, { silent: true });
        //} else {
        //    scope.set('state:height', el.offsetHeight, { silent: true });
        //    scope.set('state:width', el.offsetWidth, { silent: true });
        //}
    }));

    document.querySelectorAll('[xo-attribute="text()"]').forEach(el => observer.observe(el, { characterData: true, subtree: true }));
    document.querySelectorAll('[xo-attribute="text()"]').forEach(el => el.addEventListener('blur', function () {
        let target = event.target;
        let new_text = target.textContent;
        let scope = target.scope;
        if (scope) scope.set(new_text);
    }))
}

xover.evaluateParams = function (document = window.document) {
    let params = document.select(`//xo-param/@name`);
    if (!params.length) return;
    //document.original = document.cloneNode(true);
    document.parameters = document.parameters || new Map();

    parameters = Object.fromEntries(params.map(el => [`$${el.value}`, (function () { return eval.apply(this, arguments) }(el.parentNode.textContent || el.parentNode.getParameter("value")))]));
    document.select(`//xo-value/@select`).forEach(el => el.parentNode.textContent = parameters[el.value]);
    document.select(`//@*[contains(.,'{$')]`).forEach(attr => document.parameters.set(attr, attr.value))
    for (let [attr, formula] of document.parameters.entries()) {
        //if (!document.contains(attr.ownerElement)) continue;
        let new_value = formula.replace(/\{\$[^\}]*\}/g, (match) => match.substr(1, match.length - 2) in parameters ? parameters[match.substr(1, match.length - 2)] : match);
        if (attr.name == 'style') {
            if (attr.ownerElement) attr.ownerElement.style.cssText = new_value;
        } else {
            attr.set(new_value);
        }
        console.log(attr.parentNode)
    }
}

xover.restoreDocument = function (document = window.document) {
    xover.evaluateParams(document);
}

xover.json = {};

xover.listener = new Map();
xover.listener.Event = function (event_name, params = {}, context = (event || {}).srcElement) {
    if (!(this instanceof xover.listener.Event)) return new xover.listener.Event(event_name, params, context);
    let _event = new CustomEvent(event_name, { detail: params, cancelable: true });
    let _srcEvent = event;
    Object.defineProperty(_event, 'srcEvent', {
        get: function () {
            return _srcEvent;
        }
    })
    Object.defineProperty(_event, 'context', {
        get: function () {
            return context;
        }
    })
    if (context instanceof Node) {
        _event.detail["node"] = _event.detail["node"] || context;
        _event.detail["target"] = _event.detail["target"] || context;
        node = context
    }
    if (context instanceof Attr) {
        _event.detail["element"] = _event.detail["element"] || context.parentNode;
        _event.detail["attribute"] = _event.detail["attribute"] || context;
        _event.detail["value"] = _event.detail.hasOwnProperty("value") ? _event.detail["value"] : context.value;
        _event.detail["store"] = _event.detail["store"] || context.ownerDocument.store;
        node = context
    } else if (context instanceof Element) {
        _event.detail["element"] = _event.detail["element"] || context;
        _event.detail["value"] = _event.detail.hasOwnProperty("value") ? _event.detail["value"] : context.textContent;
        _event.detail["store"] = _event.detail["store"] || context.ownerDocument.store;
        node = context
    } else if (context instanceof Document) {
        _event.detail["document"] = _event.detail["document"] || context;
        _event.detail["store"] = _event.detail["store"] || context.store;
        _event.detail["target"] = _event.detail["target"] || context.documentElement;
    } else if (context instanceof xover.Store) {
        //_event.detail["tag"] = _event.detail["tag"] || context.tag;
        _event.detail["store"] = _event.detail["store"] || context;
        _event.detail["target"] = _event.detail["target"] || context.documentElement;
    } else if (context instanceof xover.Source) {
        //_event.detail["tag"] = _event.detail["tag"] || context.tag;
        _event.detail["source"] = _event.detail["source"] || context;
        _event.detail["target"] = _event.detail["target"] || context.documentElement;
    } else if (context instanceof Response) {
        _event.detail["response"] = _event.detail["response"] || context;
        _event.detail["request"] = _event.detail["request"] || context.request;
        _event.detail["target"] = _event.detail["target"] || context.documentElement;
        _event.detail["document"] = _event.detail["document"] || context.document;
        _event.detail["body"] = _event.detail["body"] || context.body;
        //_event.detail["tag"] = _event.detail["tag"] || context.tag;
        node = _event.detail["return_value"] || context.document;
        node = node instanceof Document && node.documentElement || node;
    }
    if (context) {
        _event.detail["tag"] = _event.detail["tag"] || context.tag;
    }
    //if (_event.detail["store"]) {
    //    _event.detail["tag"] = _event.detail["tag"] || _event.detail["store"].tag;
    //}
    ////Object.setPrototypeOf(_event, CustomEvent.prototype);
    ////Object.setPrototypeOf(_event, xover.listener.Event.prototype);
    return _event;
}
xover.listener.Event.prototype = Object.create(CustomEvent.prototype);

Object.defineProperty(xover.listener, 'matches', {
    value: function (context, event_type) {
        let [scoped_event, predicate] = event_type.split(/::/);
        event_type = scoped_event;

        context = context instanceof Window && event_type.split(/^[\w\d_-]+::/)[1] || context;
        let tag = context.tag || '';
        let fns = new Map();
        if (!context.disconnected && xover.listener.get(event_type)) {
            for (let [, handler] of ([...xover.listener.get(event_type).values()].map((predicate) => [...predicate.entries()]).flat()).filter(([predicate]) => !predicate || predicate === tag || typeof (context.matches) != 'undefined' && context.matches(predicate)).filter(([, handler]) => !handler.scope || handler.scope.prototype && context instanceof handler.scope || existsFunction(handler.scope.name) && handler.scope.name == context.name)) {
                fns.set(handler.toString(), handler);
            }
        }
        return fns;
    },
    writable: false, enumerable: false, configurable: false
})

Object.defineProperty(xover.listener, 'dispatcher', {
    value: async function (event) {
        if (xover.init.status != 'initialized') {
            await xover.init();
        }
        /*Los listeners se adjuntan y ejecutan en el orden en que fueron creados. Con este método se ejecutan en orden inverso y pueden detener la propagación para quitar el comportamiento de ejecución natural. Se tienen que agregar con el método */
        let context = event.context || event.target;
        if (typeof (context) == 'string') return;
        let fns = xover.listener.matches(context, event.type);
        let handlers = new Map([...fns, ...new Map((event.detail || {}).listeners)]);
        context.eventHistory = context.eventHistory || new Map();
        for (let handler of [...handlers.values()].reverse()) {
            if (context.eventHistory.get(handler)) {
                console.warn(`Event ${event.type} recursed`)
            }
            context.eventHistory.set(handler, true);
            //console.log(`Dispatching event: ${event.type}`)
            //console.log(handler)
            let returnValue = /*await */handler.apply(context, event instanceof CustomEvent && (event.detail instanceof Array && [...event.detail, event] || event.detail && [{ event: event, ...event.detail }, event] || [event]) || arguments); /*Events shouldn't be called with await, but can return a promise*/
            if (returnValue !== undefined) {
                event.returnValue = returnValue;
                if (event.detail) {
                    event.detail.returnValue = returnValue;
                }
            }
            if (event.srcEvent) {
                event.srcEvent.returnValue = event.returnValue;
            }
            if (event.srcEvent && event.defaultPrevented) {
                event.srcEvent.preventDefault();
            }
            if (event.srcEvent && event.cancelBubble) {
                event.srcEvent.stopPropagation();
            }
            if (event.propagationStopped) break;
            context.eventHistory.set(handler, undefined);
        }
    },
    writable: true, enumerable: false, configurable: false
});

Object.defineProperty(xover.listener, 'on', {
    value: function (name__or_list, handler, options = {}) {
        if (xover.init.status != 'initialized') {
            xover.init();
        }
        name__or_list = name__or_list instanceof Array && name__or_list || [name__or_list];
        for (let event_name of name__or_list) {
            let [scoped_event, ...predicate] = event_name.split(/::/);
            predicate = predicate.join("::");
            [base_event, scope] = scoped_event.split(/:/).reverse();
            window.top.removeEventListener(base_event, xover.listener.dispatcher);
            window.top.addEventListener(base_event, xover.listener.dispatcher);

            handler.scope = scope && eval(scope) || undefined;
            let event_array = xover.listener.get(base_event) || new Map();
            let handler_map = event_array.get(handler.toString()) || new Map();
            handler_map.set(predicate, handler);
            event_array.set(handler.toString(), handler_map);
            xover.listener.set(base_event, event_array);

            if (predicate) {
                window.top.removeEventListener(`${base_event}::${predicate}`, xover.listener.dispatcher);
                window.top.addEventListener(`${base_event}::${predicate}`, xover.listener.dispatcher);
            }
        }
    },
    writable: true, enumerable: false, configurable: false
});

xover.listener.on('hashchange', function (new_hash, old_hash) {
    xover.site.active = location.hash;
});

xover.listener.on('pushstate', function ({ state }) {
    if (typeof HashChangeEvent !== "undefined") {
        window.dispatchEvent(new HashChangeEvent("hashchange"));
        return;
    }

    try {
        window.dispatchEvent(new Event("hashchange"));
        return;
    } catch (error) {
        const ieEvent = document.createEvent("Event");
        ieEvent.initEvent("hashchange", true, true);
        window.dispatchEvent(ieEvent);
    }
});

xover.listener.on('beforeHashChange', function (new_hash, old_hash) {
    new_hash = (new_hash || window.location.hash);
    if (new_hash === '#' || document.getElementById(new_hash.substr(1)) || !(new_hash in xover.sources)) {
        event.preventDefault();
    }
})

xover.listener.on('keyup', async function (event) {
    if (event.keyCode == 27) {
        let first_alert = document.querySelector("[role='alertdialog']:last-of-type");
        first_alert && first_alert.remove();
    }
})

xover.listener.on('popstate', async function (event) {
    //if (event.defaultPrevented) return;
    //if (this.popping) {
    //    this.popping().cancel();
    //    //let current_hash = xover.data.hashTagName();
    //    //history.replaceState({
    //    //    hash: current_hash
    //    //    , history: ((history.state || {}).history || [])
    //    //}, event.target.textContent, current_hash);
    //    this.popping = undefined;
    //}
    //function popstate() {
    //    let finished = false;
    //    let cancel = () => finished = true;
    xover.session.store_id = xover.session.store_id;
    xover.site.seed = (event.state || {}).seed || (history.state || {}).seed || event.target.location.hash;
    //const promise = new Promise((resolve, reject) => {
    //    setTimeout(async () => {
    if (event.state) delete event.state.active;
    let hashtag = (xover.site.seed || '#')
    let store = xover.stores[hashtag];
    try {
        if (store) {
            await store.render()//xover.site.active == xover.site.seed || xover.site.active == store.tag);
            if (store instanceof xover.Store && !store.isRendered) {
                xover.stores.active = store;
            }
            console.log("Navigated to " + hashtag);
        } else {
            // TODO: Revisar esta sección. Puede estar desactualizada.
            //let current_hash = xover.stores.seed.tag;
            //history.replaceState({
            //    hash: current_hash
            //    , history: ((history.state || {}).history || [])
            //}, ((event || {}).target || {}).textContent, current_hash);
        }
    } catch (e) {
        console.log(e)
    }
    //            resolve();
    //        }, 500);
    //        cancel = () => {
    //            if (finished) {
    //                return;
    //            }
    //            reject();
    //        };

    //        if (finished) {
    //            cancel();
    //        }
    //    }).then((resolvedValue) => {
    //        this.popping = undefined;
    //        finished = true;
    //        return resolvedValue;
    //    }).catch((err) => {
    //        finished = true;
    //        return err;
    //    });
    //    return { promise, cancel }
    //}
    //this.popping = popstate;
    //this.popping();
})

xover.listener.on(['pageshow', 'popstate'], async function (event) {
    if (event.defaultPrevented) return;
    const positionLastShown = Number(sessionStorage.getItem('lastPosition'));
    xover.site.seed = xover.site.seed || location.hash
    xover.restoreDocument(document);
    if (history.state) delete history.state.active;
    document.querySelectorAll(`[role=alertdialog]`).toArray().remove();
    //if (!history.state && !location.hash && positionLastShown || xover.site.position > 1 && (!((location.hash || "#") in xover.stores) || !xover.stores[xover.site.seed])) {
    //    //history.back();
    //    event.stopPropagation()
    //} else if (history.state && positionLastShown > xover.site.position) {
    //    window.top.dispatchEvent(new CustomEvent('navigatedBack', { bubbles: false }));
    //} else if (history.state && positionLastShown < xover.site.position) {
    //    window.top.dispatchEvent(new CustomEvent('navigatedForward', { bubbles: false }));
    //}
})

xover.listener.on('navigatedForward', function (event) {
    if (event.defaultPrevented) return;
    if (xover.site.seed == "#" && xover.site.position > 1 && !(xover.site.history || []).length) {
        console.log("Navigated forward");
        history.back();
    }
})

xover.listener.keypress = {};
xover.mimeTypes = {};
xover.mimeTypes["css"] = "text/css"
xover.mimeTypes["doc"] = "applicaton/msword"
xover.mimeTypes["html"] = "text/html"
xover.mimeTypes["htm"] = "text/html"
xover.mimeTypes["jpg"] = "image/jpeg"
xover.mimeTypes["jpeg"] = "image/jpeg"
xover.mimeTypes["js"] = "application/javascript"
xover.mimeTypes["json"] = "application/json"
xover.mimeTypes["map"] = "text/plain"
xover.mimeTypes["pdf"] = "application/pdf"
xover.mimeTypes["png"] = "image/png"
xover.mimeTypes["resx"] = "text/xml,application/xml,application/octet-stream"
xover.mimeTypes["text"] = "text/plain"
xover.mimeTypes["xml"] = "text/xml,application/xslt+xml"
xover.mimeTypes["xsl"] = "text/xml,text/xsl,application/xslt+xml"
xover.mimeTypes["xslt"] = "text/xml,text/xsl,application/xslt+xml"

xover.Manifest = function (manifest = {}) {
    function hasMatchingStructure(input, template) {
        // Check if both objects are of type 'object'
        if (typeof template !== 'object' || typeof input !== 'object') {
            return false;
        }

        for (const key in input) {
            // Check if the key exists in the JSON object
            if (!(key in template)) {
                return false;
            }

            //const jsonValue = template[key];
            //const templateValue = input[key];

            //// Check if the types match
            //if (typeof jsonValue !== typeof templateValue) {
            //    return false;
            //}

            //// Recursively check nested objects/arrays
            //if (typeof jsonValue === 'object' && typeof templateValue === 'object') {
            //    if (!hasMatchingStructure(jsonValue, templateValue)) {
            //        return false;
            //    }
            //}
        }

        return true;
    }

    let base_manifest = {
        "server": {},
        "sources": {},
        "stores": {},
        "stylesheets": [],
        "spaces": {},
        "settings": {}
    }
    if (manifest && !hasMatchingStructure(manifest, base_manifest)) {
        throw (`Manifest has an invalid structure`);
    }
    let _manifest = Object.assign(base_manifest, manifest);

    Object.setPrototypeOf(_manifest, xover.Manifest.prototype);

    return _manifest;
}

Object.defineProperty(xover.Manifest.prototype, 'getSettings', {
    value: function (input, config_name) { //returns array of values if config_name is sent otherwise returns entries
        let tag_name = typeof (input) == 'string' && input || input && input.tag || input instanceof Node && (input.documentElement || input).nodeName || "";
        let settings = Object.entries(this.settings).filter(([key, value]) => value.constructor === {}.constructor && (tag_name === key || key[0] === '.' && tag_name && tag_name.endsWith(key) || key[0] === '^' && tag_name && tag_name.match(RegExp(key, "i")) || !['#', '^', '.'].includes(key[0]) && (input instanceof xover.Store || input instanceof Document) && input.selectSingleNode(key))).reduce((config, [key, value]) => { config.push(...Object.entries(value)); return config }, []);
        if (config_name) {
            settings = settings.filter(([key, value]) => key === config_name).map(([key, value]) => value.constructor === {}.constructor && Object.entries(value) || value);
            settings = settings.flat();
        }
        return settings;
    },
    writable: true, enumerable: false, configurable: false
});
xover.manifest = new xover.Manifest();
xover.messages = {};
xover.server = new Proxy({}, {
    get: function (self, key) {
        if (key in self) {
            return self[key]
        }
        if (!(xover.manifest.server && xover.manifest.server[key])) {
            return Promise.reject(`Endpoint "${key}" not configured in manifest`);
        }
        let return_value, request, response;
        let handler = (async function (payload, ...args) {
            let settings = {};
            if (this instanceof xover.Source || this instanceof Document) {
                settings = this.settings || {};
            }
            //let settings = this.settings || {};
            //this.settings = settings.merge(Object.fromEntries(xo.manifest.getSettings(`server:${key}`) || []));
            let url = new xover.URL(xover.manifest.server[key], undefined, { payload, ...settings.merge(Object.fromEntries(xo.manifest.getSettings(`server:${key}`) || [])) });
            request = new xover.Request(url);
            request.tag = `#server:${key}`;
            window.top.dispatchEvent(new xover.listener.Event(`beforeFetch`, { url, request, href: url.href }, request));
            try {
                [return_value, request, response] = await xover.fetch.apply(request, [url, ...args]).then(response => [response.body, response.request, response]);
            } catch (e) {
                [return_value, request, response] = [e.body, e.request, e]
                if (e instanceof DOMException) {
                    if (e.name == 'AbortError') {
                        response = new Response(response.message, { status: 499, statusText: "Client Closed Request" })
                    }
                }
            }
            response.tag = `#server:${key}`;
            let manifest_settings = xover.manifest.getSettings(response.tag, "stylesheets");
            document instanceof XMLDocument && manifest_settings.reverse().map(stylesheet => {
                return_value.addStylesheet(stylesheet);
            });
            response.response_value = return_value;
            if (response.ok) {
                window.top.dispatchEvent(new xover.listener.Event(`success`, { response, url, payload: url.settings.body, request, tag: `#server:${key}` }, response));
                return Promise.resolve(return_value);
            } else {
                window.top.dispatchEvent(new xover.listener.Event(`failure`, { response, url, payload: url.settings.body, request, tag: `#server:${key}` }, response));
                return Promise.reject(response.body);
            }
        })

        if (self.hasOwnProperty(key)) {
            Object.defineProperty(self[key], 'fetch', {
                value: function (...args) {
                    let settings = args.pop() || {};
                    if (settings.constructor === {}.constructor) {
                        settings["method"] = 'GET';
                    }
                    args.push(settings)
                    return handler.apply(this, args);
                },
                writable: true, enumerable: false, configurable: false
            });
            Object.defineProperty(self[key], 'post', {
                value: function (...args) {
                    let settings = args.pop() || {};
                    if (settings.constructor === {}.constructor) {
                        settings["method"] = 'POST';
                    }
                    args.push(settings)
                    return handler.apply(this, args);
                },
                writable: true, enumerable: false, configurable: false
            });
            return self[key];
        } else if (!(xover.manifest.server && xover.manifest.server[key])) {
            throw (new Error(`Endpoint "${key}" not configured`));
        } else {
            return handler;
        }
    }, has: function (self, key) {
        return key in self || key in (xover.manifest.server || {});
    }
})

xover.session = new Proxy({}, {
    get: function (self, key) {
        let item;
        if (key in self) {
            item = self[key];
        } else {
            item = xover.session.getKey(key);
        }
        if (item instanceof Array) {
            for (let prop of ['pop', 'push', 'splice', 'shift', 'unshift', 'remove', 'removeAll']) {
                Object.defineProperty(item, prop, {
                    value: function () {
                        let result = Array.prototype[prop].apply(item, arguments);
                        xover.session[key] = item;
                        return result;
                    }, writable: true, enumerable: true, configurable: false
                })
            }
        }
        return item;
    },
    set: async function (self, key, new_value) {
        let old_value = xover.session.getKey(key);
        let before = new xover.listener.Event(`beforeChange::session:${key}`, { attribute: key, value: new_value, old: old_value }, this);
        window.top.dispatchEvent(before);
        if (before.cancelBubble || before.defaultPrevented) return;
        xover.session.setKey(key, new_value);
        var key = key, new_value = new_value;
        window.top.dispatchEvent(new xover.listener.Event(`change::session:${key}`, { attribute: key, value: new_value, old: old_value }, this));
        xover.site.sections.map(el => [el, el.store && el.store.sources[el.getAttribute("xo-stylesheet")]]).filter(([el, stylesheet]) => stylesheet && stylesheet.selectSingleNode(`//xsl:stylesheet/xsl:param[starts-with(@name,'session:${key}')]`)).forEach(([el]) => el.render());

        ["status"].includes(key) && await xover.stores.active.render();

        if (xover.session.network_id) {
            xover.storage.setKey(key, new_value);
            xover.storage.setKey(key, undefined);
        }
        return self[key];
    },
    deleteProperty: function (self, key) {
        xover.session[key] = undefined;
    },
    has: function (self, key) {
        return key in self || key in sessionStorage
    }
})

Object.defineProperty(xover.session, 'getKey', {
    value: function (key) {
        if (typeof (Storage) !== "undefined") {
            var value = JSON.parse(sessionStorage.getItem(key));
            if (!(key in sessionStorage)) {
                return undefined;
            } else if (value == "null" || value == "undefined") { //Para guardar específicamente null o undefined, se guardarían como texto plano;
                return eval(value);
                //} else if (value && key.indexOf("#") != -1) {
                //    return (xover.xml.createDocument(value, false) || value);
            } else if (key in sessionStorage) {
                return value;
            } else {
                return value; //Se está considerando que si no existe el key, estaría regresando null (si el valor que se quiso guardar fue null, se habría guardado como "null" y se habría atendido en la primer condición). En este caso es mejor definirlo como undefined (no se ha definido)
            }
        } else {
            console.error('Storage is not supported by your browser')
        }
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.session, 'setKey', {
    value: function (key, value) {
        if (typeof (Storage) !== "undefined") {
            if (value instanceof Promise) {
                return false;
            } else if (value === undefined) {
                sessionStorage.removeItem(key);
            } else if (value instanceof Attr) {
                sessionStorage.setItem(key, JSON.stringify({ attribute: value.name, value: value.value, target: value.parentNode.getAttribute("xo:id") }));
            } else if ((value instanceof Node || value instanceof xover.Store) && value.toString) {
                sessionStorage.setItem(key, JSON.stringify(value.toString()));
            } else if (value instanceof Node && value.outerHTML) {
                sessionStorage.setItem(key, JSON.stringify(value.outerHTML));
            } else {
                sessionStorage.setItem(key, JSON.stringify(value));
            }
        } else {
            console.error('Storage is not supported by your browser')
        }
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.session, 'getCurrentStatus', {
    value: async function () {
        return xover.session.checkStatus();
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.session, 'checkStatus', {
    value: async function (settings) {
        if (!(navigator.onLine || 'status' in xover.server)) return xover.session.status;
        let server_status = {};
        //if (!((xover.manifest.server || {}).session)) {
        //    return Promise.reject(new Error("Session endpoint not configured."));
        //}
        if ('status' in xover.server) {
            try {
                server_status = await xover.server.status();
            } catch (e) {
                server_status = { "status": "unauthorized" }
            }
        }
        return new Promise((resolve, reject) => {
            let current_status = xover.session.status;
            xover.session.updateSession(server_status);
            if (current_status != server_status.status) {
                xover.stores.active.render();
            }
            resolve(server_status["status"]);
        });
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.session, 'login', {
    value: function () {
        if ('login' in xover.server) {
            try {
                return xover.server.login.apply(xover.server.login, arguments);
            } catch (e) {
                console.error(e);
            }
        } else {
            xover.session.status = 'authorized';
            return false;
        }
    }
    , writable: true, enumerable: false, configurable: true
});

Object.defineProperty(xover.session, 'logout', {
    value: function () {
        if ('logout' in xover.server) {
            try {
                return xover.server.logout.apply(xover.server.logout, arguments);
            } catch (e) {
                console.error(e);
            }
        } else {
            xover.session.status = 'unauthorized';
            xover.init();
            return false;
        }
    }
    , writable: true, enumerable: false, configurable: true
});

Object.defineProperty(xover.session, 'use', {
    value: function (store_id, without_confirmation) {
        if (!(xover.session.store_id == store_id)) {
            if (!without_confirmation && confirm("Change connection?")) {
                xover.session.store_id = store_id;
                xover.session.logout();
            }
        }
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.session, 'saveLocation', {
    value: function (key, value) {
        xover.session.setKey("xover.current_location", window.location.pathname.replace(/[^/]+$/, ""));
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.session, 'getLocation', {
    value: function () {
        return xover.session.getKey("xover.current_location");
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.session, 'setData', {
    value: function (data) {
        if (typeof (Storage) !== "undefined") {
            if (data && data.documentElement) {
                data = data.documentElement.outerHTML;
            }
            xover.session.setKey(location.pathname.replace(/[^/]+$/, "") + "xover.data", data);
        }
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.session, 'clearCache', {
    value: function (options) {
        var { auto_reload = true } = (options || {});
        if (typeof (Storage) !== "undefined") {
            sessionStorage.clear();
            navigator.serviceWorker && navigator.serviceWorker.getRegistrations().then(function (registrations) {
                for (let registration of registrations) {
                    registration.unregister()
                }
            }).then(() => {
                typeof (caches) != 'undefined' && caches.keys()
                    .then(cacheNames => {
                        return Promise.all(
                            cacheNames.map(cacheName => {
                                return caches.delete(cacheName)
                            })
                        )
                    }).then(() => auto_reload && window.location.reload(true))
            })
            //xover.stores.clear();

        } else {
            console.error('Storage is not supported by your browser')
        }
    },
    writable: false, enumerable: false, configurable: false
});

xover.site = new Proxy(Object.assign({}, history.state), {
    get: function (self, key) {
        let proxy = self;
        if (!history.state) {
            with ((window.top || window)) {
                //history.replaceState({}, {}, location.pathname + location.search + (location.hash || ''));
                history.replaceState(Object.assign({ position: history.length - 1 }, history.state), {}, location.pathname + location.search + (location.hash || ''));
            }
            xover.session.setKey('lastPosition', self.position);
        }
        if (self.hasOwnProperty(key)) {
            return self[key];
        } else {
            return xover.session.getKey(key);
        }
    },
    set: function (self, key, new_value) {
        try {
            self[key] = new_value;
            if (key === 'seed') xover.site['active'] = new_value
            let hash = [xover.manifest.getSettings(self['active'], 'hash').pop(), self['active'], ''].coalesce();
            history.replaceState(Object.assign({ position: history.length - 1 }, history.state), ((event || {}).target || {}).textContent, location.pathname + location.search + hash);

            ////let pending_stylesheets = xover.site.sections.map(el => el.stylesheet).filter(doc => doc && !doc.documentElement)

            ////Promise.all(pending_stylesheets.map(document => document.fetch())).then(() => {
            //if (['active'].includes(key)) {
            //    xover.site.sections.filter(el => el.closest('[xo-store="active"]')).forEach(el => el.render());
            //}
            ////})
        } catch (e) {
            console.error(e);
        }
    }
})

Object.defineProperty(xover.site, 'reference', {
    get() { return (history.state['reference'] || {}) }
    , set() { throw `State "reference" is readonly` }
    , enumerable: true
});

Object.defineProperty(xover.site, 'history', {
    get() { return (history.state['history'] || []) }
    , set() { throw `State "history" is readonly` }
    , enumerable: true
});

Object.defineProperty(xover.site, 'hash', {
    get() { return location.hash }
    , set(input) {
        input = input[input.length - 1] != '#' ? input : '';
        history.replaceState(Object.assign({ position: history.length - 1 }, history.state, { active: history.state.active }), ((event || {}).target || {}).textContent, location.pathname + location.search + (input || ''));
    }
    , enumerable: false
});

Object.defineProperty(xover.site, 'querystring', {
    get() {
        return new URLSearchParams(location.search)
    }
    , enumerable: false
});

Object.defineProperty(xover.site, 'state', {
    get() {
        history.state['state'] = history.state['state'] || {};
        return history.state['state'];
    }
    , set(input) { history.state['state'] = input }
    , enumerable: true
});

Object.defineProperty(xover.site, 'sections', {
    get() {
        let sections = new Proxy([...top.window.document.querySelectorAll(`[xo-stylesheet]`)], {
            get: function (self, key) {
                if (key in self) {
                    return self[key]
                } else {
                    let [stylesheet_href, store_name] = key.split(/#/);
                    let store = store_name && xover.stores['#' + store_name];
                    return self.filter(section => (store && section.store == store || !store) && section.getAttribute("xo-stylesheet") == stylesheet_href)
                }
            }
        });
        Object.defineProperty(sections, 'active', {
            get() {
                let active_element = xover.site.activeElement;
                let active_section = active_element.closest(`[xo-stylesheet]`) || this.filter(section => section.store.tag == xover.site.active).find(section => xo.stores.seed.stylesheets.map(stylesheet => stylesheet.href).includes(section.getAttribute("xo-stylesheet")));
                return active_section;
            }
        })
        return sections;
    }
    , enumerable: false
});

Object.defineProperty(xover.site.sections, 'render', {
    value() {
        this.forEach(section => section.render())
    }, writable: false, configurable: false, enumerable: false
});

Object.defineProperty(xover.site, 'set', {
    value(input, value) {
        let prop;
        if (input instanceof Node) {
            prop = input.name;
            value = input.value
        } else if (typeof (input) === 'string') {
            prop = input
        } else if (input instanceof Array) {
            for (el of input) {
                this.set(el.name, new Object().push(el.parentNode.getAttribute("xo:id"), el.value))
            }
            return
        } else {
            let entries = Object.entries(input);
            prop = entries[0][0];
            value = value !== undefined ? value : entries[0][1]
        }
        let { prefix, name } = xover.xml.getAttributeParts(prop);
        let active = this.active;
        let site_state = this.state;
        site_state[active] = (site_state[active] || {});
        if (prefix) {
            site_state[active][prefix] = (site_state[active][prefix] || {});
        }
        if (value instanceof Array) {
            if (prefix) {
                site_state[active][prefix][name] = site_state[active][prefix][name] || []
                site_state[active][prefix][name] = value
            } else {
                site_state[active][name] = site_state[active][name] || [];
                site_state[active][name] = value
            }
        } else if (value instanceof Object) {
            if (prefix) {
                site_state[active][prefix][name] = site_state[active][prefix][name] || {}
                site_state[active][prefix][name] = value;
            } else {
                site_state[active][name] = site_state[active][name] || {};
                site_state[active][name] = value;
            }
        } else {
            value = (value !== null && value !== undefined && !(value instanceof Array) ? value.toString() : value);
            if (value === undefined) {
                if (prefix) {
                    delete site_state[active][prefix][name]
                } else {
                    delete site_state[active][name];
                }
            } else {
                if (prefix) {
                    site_state[active][prefix][name] = value
                } else {
                    site_state[active][name] = value;
                }
            }
        }

    }
    , enumerable: false
});

Object.defineProperty(xover.site, 'get', {
    value(prop, initial) {
        let { prefix, name } = xover.xml.getAttributeParts(prop);
        let active = this.active;
        let site_state = this.state;
        site_state[active] = (site_state[active] || {});
        let returnValue;
        if (prefix) {
            if (initial) {
                returnValue = (site_state[active][prefix] || {})[name];
                if (returnValue == undefined) {
                    xover.site.set(prop, initial)
                }
                (site_state[active][prefix] || {})[name] = initial;
            }
            return (site_state[active][prefix] || {})[name];
        } else {
            if (initial) {
                returnValue = (site_state[active] || {})[name];
                if (returnValue == undefined) {
                    xover.site.set(prop, initial)
                }
            }
            return site_state[active][name];
        }
    }
    , enumerable: false
});

Object.defineProperty(xover.site, 'activeCaret', {
    get() {
        let active = this.active;
        let site_state = this.state;
        return (site_state[active] || {})["activeCaret"];
    }
    , set(input) {
        let active = this.active;
        let site_state = this.state;
        site_state[active] = (site_state[active] || {});
        site_state[active]["activeCaret"] = input;
    }
    , enumerable: false
});

Object.defineProperty(xover.site, 'activeElement', {
    get() {
        targetDocument = ((document.activeElement || {}).contentDocument || document);
        let active = this.active;
        let site_state = this.state;
        return targetDocument.querySelector((site_state[active] || {})["activeElement"]) || (document.activeElement || {});
    }
    , set(input) {
        if (input instanceof Node) input = input.selector;
        let active = this.active;
        let site_state = this.state;
        site_state[active] = (site_state[active] || {});
        site_state[active]["activeElement"] = input;
    }
    , enumerable: false
});

Object.defineProperty(xover.site, 'next', {
    get() { return (history.state['next'] || {}) }
    , set(input) { history.state['next'] = input }
    , enumerable: false
});

Object.defineProperty(xover.site, 'seed', {
    get() { return (history.state['seed'] || location.hash || '#') }
    , set(input) {
        if (!history.state['seed']) {
            history.state['seed'] = input;
            //xover.site.active = input;
        } else if (new xo.URL(history.state['seed']).hash != new xo.URL(input).hash) {
            xover.site.next = input;
            let reference = event && event.srcElement || {};
            let ref_node = reference.scope;
            let prev = [...this["history"]];
            prev.unshift({
                store: (reference.store || {}).tag || null
                , reference: {
                    id: (ref_node && ref_node.ownerElement || ref_node || document.createElement('p')).getAttribute("xo:id") || null
                    , attribute: ref_node instanceof Attr && ref_node.name || null
                }
            });
            let new_state = Object.assign({}, history.state); //If state is not copied, attributes that are not present like "stores", might be lost
            //new_state["position"] = history.state.position++;
            //new_state["scrollableElements"] = {};
            new_state["seed"] = input;
            new_state["history"] = prev;
            new_state["next"] = "";
            new_state["position"] = new_state["position"] + 1;
            xover.session.setKey('lastPosition', new_state["position"]);
            history.pushState(Object.assign({ position: history.length - 1 }, new_state), ((event || {}).target || {}).textContent, (xover.stores[input] || {}).tag);
        }
    }
    , enumerable: true
});

Object.defineProperty(xover.site, 'position', {
    get() { return [history.state['position'], Number(this.history.length) + 1].coalesce() }
    , set(input) { history.go(input - xover.site.position) }
    , enumerable: true
});

Object.defineProperty(xover.site, 'active', {
    get: function () {
        if (xover.session.getKey("status") != 'authorized' && 'login' in xover.server) {
            return "#login";
        } else {
            return history.state.active || this.seed;
        }
    },
    set: function (input) {
        /* No debe ser modificable */
        //Object.defineProperty(this, 'active', { value: input });
        //xover.stores.active.render(/*true*/);
        //let hash = [xover.stores[input].hash, (window.top || window).location.hash].coalesce();
        //xover.dom.navigateTo(hashtag)
        input = input || "#";
        history.state.active = input;//Revisar si no lo tiene que guardar, porque en el caso del login, sobreescribiría el estado y lo perderíamos. Este truco se va a tener que hacer directo con history.state.active
        let active = this.active;
        let store = xover.stores[active];
        if (!store) {
            let source = xover.sources[active];
            store = new xover.Store(source, { tag: source.tag });
        }
        if (store) {
            this.hash = store.hash;
        } else {
            return Promise.reject(`${active} no available`)
        }
        if (!this.sections.find(section => section.store && section.store.tag == active)) {
            store && store.render();
        }
    }
    , enumerable: false
});

Object.defineProperty(xover.site, 'activeTags', {
    get: function () {
        return function (tag) {
            let active_tag = tag || (xover.stores[this.active] || {}).tag || this.active; //se hace de esta manera porque el estado podría guardar como active el tag "#"
            this.state[active_tag] = this.state[active_tag] || {};
            let active_stores = (this.state[active_tag] || {}).active;
            return active_stores || [(xover.stores[this.active] || {}).tag].filter(tag => tag);
        }
    }
    , set: function (input) {
        let self = this;
        let active = self.active;
        let site_state = self.state;
        site_state[active] = (site_state[active] || {});
        site_state[active]["active"] = input;
    }
    , enumerable: false
});

Object.defineProperty(xover.site, 'update', {
    value: function (new_state) {
        if (!new_state) return;
        let new_active = new_state['active'];
        delete new_state['active'];
        for (let prop in new_state) this[prop] = new_state[prop];
        if (new_active) {
            history.state.active = new_active;
            this.active = new_active;
        }
    }
    , writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.site, 'goto', {
    value: function (href, state) {
        xover.site.seed = href;
    }
    , writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.site, 'save', {
    value: function (srcElement) {
        //xover.delay(1).then(() => {
        //srcElement = (srcElement || event && event.srcElement);
        targetDocument = ((document.activeElement || {}).contentDocument || document);
        //if (srcElement && !(srcElement instanceof HTMLElement) || !targetDocument.querySelector('*')) {
        //    return
        //}
        try {
            srcElement = srcElement || targetDocument.querySelector(this.activeElement.selector || 'body');
        } catch (e) {
            console.error(e)
        }
        if (srcElement) {
            this.activeElement = srcElement.selector || srcElement;
            this.activeCaret = xover.dom.getCaretPosition(srcElement);
        }
        history.replaceState(Object.assign({}, history.state), {}, location.pathname + location.search + (location.hash || ''));
    }
    , enumerable: false, configurable: false
});

Object.defineProperty(xover.site, 'restore', {
    value: function (scope) {
        targetDocument = (scope || (document.activeElement || {}).contentDocument || document);
        let scrollableElements = xover.site.getScrollableElements(targetDocument);
        for (let element of scrollableElements) {
            let [, coordinates = { x: 0, y: 0 }] = Object.entries(xover.site.get("scrollableElements", {})).find(([selector, coordinates]) => element.matches(selector)) || [];
            xover.dom.setScrollPosition(element, coordinates);
        }

        let activeElement = xover.site.activeElement;
        if (!activeElement) {
            return;
        }
        xover.dom.triggeredByTab = undefined;
        if (scope && scope.contains(activeElement)) {
            xover.dom.setCaretPosition(activeElement, xover.site.activeCaret);
        }
    }
    , enumerable: false, configurable: false
});

xover.xml = {};

xover.xml.createDocument = function (xml, options = { autotransform: true }) {
    let result = undefined;
    if (xml instanceof XMLDocument) {
        result = xml.cloneNode(true);
    } else {
        var sXML = (xml && xml.document || xml || '').toString();
        if (sXML.indexOf('<<<<<<< ') != -1) {
            throw (new Error("Possible unresolved GIT conflict on file."));
        }
        parser = new DOMParser();
        if (!sXML) {
            result = document.implementation.createDocument("http://www.w3.org/XML/1998/namespace", "", null);
        } else {
            if (xml.namespaceURI && xml.namespaceURI.indexOf("http://www.w3.org") == 0) {
                result = parser.parseFromString(sXML, "text/html");
            } else {
                let escaped_line_breaks
                result = parser.parseFromString(sXML.replace(/[\u0000-\u001F]/g, (char) => ['\r', '\n', '\t'].includes(char) && char || '').replace(/\w+="[^"]+[\n\r]+[^"]+"/ig, (attr) => {
                    escaped_line_breaks = true;
                    attr = attr.replace(/\r\n/ig, "&#10;");
                    attr = attr.replace(/\t/ig, "&#9;");
                    return attr
                }), "text/xml");
            }
            if (sXML && result.getElementsByTagName && (result.getElementsByTagName('parsererror').length || 0) > 0) {
                for (let message of [...result.querySelectorAll('parsererror div')]) {
                    if (String(message.textContent).match(/prefix|prefijo/)) {
                        var prefix = (message.textContent).match(/(?:prefix|prefijo)\s+([^\s]+\b)/).pop();
                        if (!xover.spaces[prefix]) {
                            //xml.documentElement.appendChild(message.documentElement);
                            return Promise.reject(message.textContent.match("(error [^:]+):(.+)"));
                        }
                        //(xml.documentElement || xml).setAttributeNS('http://www.w3.org/2000/xmlns/', "xmlns:" + prefix, xover.spaces[prefix]);
                        sXML = sXML.replace(new RegExp(`^(<[^\\s\/>]+)`), `$1 xmlns:${prefix}="${xover.spaces[prefix] || ''}"`);
                        result = xover.xml.createDocument(sXML, options);
                        return result;
                    } else if (message.closest("html") && String(message.textContent).match(/Extra content at the end of the document/)) {
                        message.closest("html").remove();
                        //result = document.implementation.createDocument("http://www.w3.org/XML/1998/namespace", "", null);
                    } else if (String(message.textContent).match(/Extra content at the end of the document/)) {
                        let frag = window.document.createDocumentFragment();
                        let p = window.document.createElement('p');
                        p.innerHTML = xml;
                        frag.append(...p.childNodes);
                        return frag;
                    } else if (message.closest("html")) {
                        if (options["silent"] !== true) {
                            xover.dom.createDialog(message.closest("html"));
                        }
                        throw (new Error(message.textContent));
                    } else {
                        return Promise.reject(message.textContent.match("(error [^:]+):(.+)").pop())
                    }
                }
            }
        }
    }

    //if (options["autotransform"]) {
    if (result.documentElement && !["http://www.w3.org/1999/xhtml", "http://www.w3.org/1999/XSL/Transform"].includes(result.documentElement.namespaceURI)) {
        xover.manifest.getSettings(result, 'stylesheets').reverse().forEach(stylesheet => result.addStylesheet(stylesheet));
    }
    //    // Considerar quitar esta parte de aquí. 
    //    (result.stylesheets || []).filter(stylesheet => stylesheet.role == 'init').forEach(stylesheet => {
    //        if (stylesheet.document.documentElement instanceof Document) {
    //            let new_document = result.transform(stylesheet.document);
    //            if ((((new_document.documentElement || {}).namespaceURI || '').indexOf("http://www.w3.org") == -1)) {
    //                new_document.stylesheets[stylesheet.href].replaceBy(result.createComment('Initialized by ' + stylesheet.href));
    //                /*La transformación no debe regresar un html ni otro documento del estándar*/
    //                result = new_document;
    //            } else {
    //                delete stylesheet["role"];
    //                result.addStylesheet(stylesheet);
    //                console.warn("Initial transformation shouldn't yield and html or any other document from the w3 standard.");
    //            }
    //        }
    //    });
    //}
    return result;
}

xover.Source = function (tag/*source, tag, manifest_key*/) {
    let expiration_ms = function (expiry) {
        if (expiry == null) return null;
        let ms = 0;
        if (typeof (expiry) == 'object') {
            ms += (expiry["d"] || 0) * 1000 * 60 * 60 * 24
            ms += (expiry["h"] || 0) * 1000 * 60 * 60
            ms += (expiry["m"] || 0) * 1000 * 60
            ms += (expiry["s"] || 0) * 1000
            ms += (expiry["ms"] || 0)
        } else {
            ms += expiry * 1000
        }
        return ms
    }
    if (!(this instanceof xover.Source)) return new xover.Source(tag/*source, tag, manifest_key*/);
    let _isActive = undefined;
    let self = this;
    let _manifest = xover.manifest.sources || {};

    let __document = xover.xml.createDocument();

    const manifest_key = Object.keys(_manifest).filter(manifest_key => manifest_key[0] === '^' && tag.match(new RegExp(manifest_key, "i")) || manifest_key === tag || tag[0] == '#' && manifest_key === '#' + xover.URL(tag.substring(1)).pathname.substring(1)).pop();

    let definition;
    if (!__document.hasOwnProperty("definition")) {
        Object.defineProperty(this, 'definition', {
            get: function () {
                if (definition !== undefined) return definition;
                if (manifest_key) {
                    let source = JSON.parse(JSON.stringify(xover.manifest.sources[manifest_key]));
                    source = manifest_key && manifest_key[0] === '^' && [...tag.matchAll(new RegExp(manifest_key, "ig"))].forEach(([...groups]) => {
                        if (typeof (source) == 'string') {
                            source = tag.replace(new RegExp(manifest_key, "i"), source)
                        } else {
                            Object.keys(source).forEach(fn => source[fn].constructor === [].constructor && source[fn].forEach((value, ix) => source[fn][ix] = value.replace(/\{\$(\d+|&)\}/g, (...args) => groups[args[1].replace("&", "0")])) || source[fn].constructor === {}.constructor && Object.entries(source[fn]).forEach(([el, value]) => source[fn][el] = value.replace(/\{\$(\d+|&)\}/g, (...args) => groups[args[1].replace("&", "0")])))
                        }
                    }) || source;
                    source = JSON.parse(JSON.stringify(source));
                    if (typeof (source) == 'string' && source[0] == '#') {
                        __document = xover.sources[source];
                        source = __document.source.definition;
                    }
                    definition = source != null ? source : tag;
                } else {
                    definition = tag;
                }
                return definition;
            }, enumerable: false, configurable: false
        });
    }

    if (!__document.hasOwnProperty("source")) {
        Object.defineProperty(__document, 'source', {
            value: this,
            writable: false, enumerable: false, configurable: false
        });
    }
    let __settings = {};
    if (!this.hasOwnProperty("settings")) {
        Object.defineProperty(this, 'settings', {
            value: __settings,
            writable: false, enumerable: false, configurable: false
        });
    }

    if (!this.hasOwnProperty("tag")) {
        Object.defineProperty(this, 'tag', {
            value: tag[0] !== '#' ? `#${tag}` : tag,
            writable: false, enumerable: false, configurable: false
        });
    }

    let _progress = 0;

    if (!this.hasOwnProperty("tag")) {
        Object.defineProperty(this, 'tag', {
            value: tag,
            writable: false, enumerable: false, configurable: false
        });
    }

    if (!this.hasOwnProperty("manifest_key")) {
        Object.defineProperty(this, 'manifest_key', {
            get: function () {
                return manifest_key;
            }, enumerable: false, configurable: false
        });
    }

    Object.defineProperty(this, 'document', {
        enumerable: true,
        get: function () {
            return __document;
        }
    });

    //Object.defineProperty(this, 'progress', {
    //    get: function () {
    //        return _progress
    //    }, set: function (input) {
    //        _progress = input;
    //        window.top.dispatchEvent(new xover.listener.Event('progress', { percent: _progress, document: __document, source: self }, self));
    //    }
    //});

    this.state = new Proxy({}, {
        get: function (target, name) {
            return target[name];
        },
        set: function (target, name, value) {
            target[name] = value
        }
    })
    Object.defineProperty(this, `fetch`, {
        value: async function (...args) {
            let source = self.definition;

            this.fetching = this.fetching || new Promise(async (resolve, reject) => {
                let new_document;
                if (!this.tag) {
                    this.tag = self.tag;
                }
                this.settings = this.settings || {};
                let before_event = new xover.listener.Event('beforeFetch', { tag: tag }, this);
                window.top.dispatchEvent(before_event);
                if (before_event.cancelBubble || before_event.defaultPrevented) return;
                let endpoints = Object.keys(source && source.constructor === {}.constructor && source || {}).filter(endpoint => endpoint.replace(/^server:/, '') in xover.server || existsFunction(endpoint)).map((endpoint) => {
                    let parameters = source[endpoint]
                    parameters = parameters && {}.constructor === parameters.constructor && Object.entries(parameters).map(([key, value]) => [key, value && value.indexOf && value.indexOf('${') !== -1 && eval("`" + value + "`") || value]) || parameters;
                    let url = xover.URL(location.hash.replace(/^#/, ''));
                    if (location.hash && url.pathname === xover.URL(tag.replace(/^#/, '')).pathname) {
                        parameters = parameters.concat([...url.searchParams.entries()])
                    }
                    if (Array.isArray(parameters) && parameters.length && parameters.every(item => Array.isArray(item) && item.length == 2)) {
                        parameters = [parameters];
                    }
                    return [endpoint, parameters]
                });
                let settings = Object.fromEntries(xover.manifest.getSettings(tag).concat(Object.entries(source && source.constructor === {}.constructor && source || []).filter(([key]) => !Object.keys(Object.fromEntries(endpoints)).includes(key))).concat(Object.entries(self.settings || {})).concat(xover.manifest.getSettings(source)));
                this["settings"].merge(settings);
                let stored_document;
                if (!xover.session.rebuild && !(source instanceof Document)) {
                    let sources = await xover.storehouse.sources;
                    stored_document = !xover.session.disableCache && await sources.get(tag + (tag === xover.site.active ? location.search : '')) || new_document;

                    let expiry = expiration_ms(this["settings"]["expiry"])
                    if (stored_document && ((Date.now() - stored_document.lastModifiedDate) > (expiry || 0))) {
                        stored_document = null;
                    }
                }
                if (stored_document) {
                    new_document = stored_document
                } else if (source && source.constructor === {}.constructor) {
                    let promises = [];
                    for (let [endpoint, parameters] of endpoints) {
                        promises.push(new Promise(async (resolve, reject) => {
                            try {
                                if (endpoint.replace(/^server:/, '') in xover.server) {
                                    new_document = await xover.server[endpoint.replace(/^server:/, '')].apply(this, parameters);
                                } else if (existsFunction(endpoint)) {
                                    let fn = eval(endpoint);
                                    new_document = await fn.apply(this, args.concat(parameters));
                                }
                            } catch (e) {
                                if (e instanceof Response && e.document instanceof XMLDocument) {
                                    if ([412].includes(e.status)) {
                                        new_document = e.document;
                                    } else {
                                        return reject(e.document)
                                    }
                                } else {
                                    return reject(e)
                                }
                            }
                            resolve(new_document);
                        }));
                    }
                    let documents;
                    try {
                        documents = await Promise.all(promises).then(document => document);
                    } catch (e) {
                        window.top.dispatchEvent(new xover.listener.Event('failure::fetch', { response: e }, this));
                        return reject(e);
                    }
                    new_document = documents[0];
                } else if (source && source[0] !== '#') {
                    try {
                        this["settings"].headers = new Headers(this["settings"].headers || {});
                        let headers = this["settings"].headers;
                        headers.set("accept", headers.get("accept") || xover.mimeTypes[source.substring(source.lastIndexOf(".") + 1)]);
                        let accept_header = headers.get("accept");
                        if (accept_header && (accept_header.indexOf('xml') != -1 || accept_header.indexOf('xsd') != -1 || accept_header.indexOf('xsl') != -1)) {
                            new_document = await xover.fetch.xml.apply(this, [source, this["settings"]]);
                        } else if (accept_header && accept_header.indexOf('json') != -1) {
                            new_document = await xover.fetch.json.apply(this, [source, this["settings"]]);
                        } else {
                            new_document = await xover.fetch.apply(this, [source, this["settings"]]);
                        }
                    } catch (e) {
                        return reject(e);
                    }
                }
                if (new_document instanceof Response) {
                    let body_element = window.document.createElement("body");
                    body_element.innerHTML = new_document.body;
                    new_document = xover.xml.createDocument(body_element);
                }
                if (!new_document) {
                    new_document = xover.sources.defaults[source];
                }
                if (!(new_document instanceof Document || new_document instanceof DocumentFragment)) {
                    return reject(`No se pudo obtener la fuente de datos ${tag}`);
                }
                settings.stylesheets && settings.stylesheets.forEach(stylesheet => new_document.addStylesheet(stylesheet));
                window.top.dispatchEvent(new xover.listener.Event(`fetch`, { document: new_document, tag, settings: this.settings }, self));
                return resolve(new_document);
            }).catch(async (e) => {
                //window.top.dispatchEvent(new xover.listener.Event('failure::fetch', { tag: tag, document: __document, response: e }, self));
                if (!e) {
                    return Promise.reject(e);
                }
                let document = e.document;
                let targets = []
                if (e.status != 404 && document && document.render) {
                    targets = await document.render();
                    if (!(targets && targets.length)) {
                        return Promise.reject(e)
                    }
                } else {
                    return Promise.reject(e);
                }
            }).finally(() => {
                this.fetching = undefined;
            });
            return this.fetching;
        },
        writable: false, enumerable: false, configurable: false
    });
    return this
}

xover.sources = new Proxy({}, {
    get: function (self, key) {
        if (key in self) {
            return self[key];
        }
        key = xover.URL(key).href;
        if (key in self) {
            return self[key];
        }

        xover.sources[key] = new xover.Source(key).document;
        return self[key];
    },
    set: function (self, key, input) {
        self[key] = input;
    },
    has: function (self, key) {
        if (!key) return false;
        return source_defined = key in self || !!Object.keys(xover.manifest.sources || {}).filter(manifest_key => manifest_key[0] === '^' && key.match(new RegExp(manifest_key, "i")) || manifest_key === key).pop()
    }
})

Object.defineProperty(xover.sources, 'defaults', {
    value: new Proxy({}, {
        get: function (self, key) {
            if (key in self) {
                return self[key].cloneNode(true);
            }
        }
    }),
    writable: false, enumerable: false, configurable: false
});

xover.sources.defaults["#login"] = xover.xml.createDocument(`<?xml-stylesheet type="text/xsl" href="login.xslt" role="login" target="body"?><xo:login xmlns:xo="http://panax.io/xover"/> `);

xover.sources.defaults["#shell"] = xover.xml.createDocument('<?xml-stylesheet type="text/xsl" href="shell.xslt" role="shell" target="body"?><shell:shell xmlns:xo="http://panax.io/xover" xmlns:shell="http://panax.io/shell" xmlns:state="http://panax.io/state" xmlns:source="http://panax.io/source" xo:id="shell" xo:hash=""></shell:shell>');

xover.sources.defaults["#settings"] = xover.xml.createDocument('<?xml-stylesheet type="text/xsl" href="settings.xslt" role="settings" target="@#shell @#settings"?><shell:settings xmlns:shell="http://panax.io/shell"/>');

xover.ProcessingInstruction = function (stylesheet) {
    if (!(this instanceof xover.ProcessingInstruction)) return new xover.ProcessingInstruction(stylesheet);
    let attribs = xover.json.fromAttributes(stylesheet.data);
    attribs["dependencies"] = [];
    if (attribs.target) {
        attribs["target"] = ((attribs["target"] || '').replace(new RegExp("@(#[^\\s\\[]+)", "ig"), `[xo-store="$1"]`) || undefined);
        attribs["dependencies"] = [...attribs["target"].matchAll(new RegExp(`\\[xo-store=('|")([^\\1\\]]+)\\1\\]`, 'g'))].reduce((arr, curr) => { arr.push(curr[2]); return arr }, []);
    } else {
        attribs["target"] = undefined;
    }
    for (let prop in attribs) {
        if (stylesheet.hasOwnProperty(prop)) continue;
        Object.defineProperty(stylesheet, prop, {
            get: function () {
                return attribs[prop];
            },
            set: function (input) {
                attribs[prop] = input
                let current_attributes = xover.json.fromAttributes(stylesheet.data);
                let new_attributes = Object.assign({}, attribs);
                delete new_attributes["target"];
                delete new_attributes["dependencies"];
                stylesheet.data = xover.json.toAttributes(Object.assign(current_attributes, new_attributes));
            }
        });
    }
    if (!stylesheet.hasOwnProperty("document")) {
        Object.defineProperty(stylesheet, 'document', {
            get: function () {
                //this.ownerDocument.store = this.ownerDocument.store || (xover.stores.find(this.ownerDocument).shift() || document.createElement('p')).store //Se pone esta solución pero debería tomar automáticamente el store. Ver si se puede solucionar este problema de raíz.
                try {
                    let store = this.ownerDocument.store;
                    href = this.href;
                    let document = store && store.sources[href] || xover.sources[href];
                    document.store = store;
                    document.href = href;
                    return document
                } catch (e) {
                    console.log(`Couldn't retrieve document for stylesheet ${this.href}: ${e.message}`)
                }
            }
        });
    }
    if (!stylesheet.href) {
        console.warn('Href attribute is missing from stylesheet!');
    }
    Object.setPrototypeOf(stylesheet, xover.ProcessingInstruction.prototype)
    return stylesheet;
}

xover.ProcessingInstruction.prototype = Object.create(ProcessingInstruction.prototype);

xover.storage = {};
xover.spaces = {};
xover.xml.namespaces = xover.spaces;

xover.spaces["context"] = "http://panax.io/context"
xover.spaces["debug"] = "http://panax.io/debug"
xover.spaces["height"] = "http://panax.io/state/height"
xover.spaces["html"] = "http://www.w3.org/1999/xhtml"
xover.spaces["js"] = "http://panax.io/xover/javascript"
xover.spaces["meta"] = "http://panax.io/metadata"
xover.spaces["metadata"] = "http://panax.io/metadata"
xover.spaces["mml"] = "http://www.w3.org/1998/Math/MathML"
xover.spaces["session"] = "http://panax.io/session"
xover.spaces["shell"] = "http://panax.io/shell"
xover.spaces["site"] = "http://panax.io/site"
xover.spaces["state"] = "http://panax.io/state"
xover.spaces["svg"] = "http://www.w3.org/2000/svg"
xover.spaces["temp"] = "http://panax.io/temp"
xover.spaces["transformiix"] = "http://www.mozilla.org/TransforMiix"
xover.spaces["width"] = "http://panax.io/state/width"
xover.spaces["xhtml"] = "http://www.w3.org/1999/xhtml"
xover.spaces["xlink"] = "http://www.w3.org/1999/xlink"
xover.spaces["xmlns"] = "http://www.w3.org/2000/xmlns/"
xover.spaces["x"] = "http://panax.io/xover"
xover.spaces["xo"] = "http://panax.io/xover"
xover.spaces["xml"] = "http://www.w3.org/XML/1998/namespace"
xover.spaces["xsi"] = "http://www.w3.org/2001/XMLSchema-instance"
xover.spaces["xson"] = "http://panax.io/xson"
xover.spaces["xsl"] = "http://www.w3.org/1999/XSL/Transform"

/* Binding */
xover.spaces["request"] = "http://panax.io/fetch/request"
xover.spaces["source"] = "http://panax.io/source"
xover.spaces["binding"] = "http://panax.io/xover/binding"
xover.spaces["changed"] = "http://panax.io/xover/binding/changed"
xover.spaces["source_text"] = "http://panax.io/source/request/text"
xover.spaces["source_prefix"] = "http://panax.io/source/request/prefix"
xover.spaces["source_value"] = "http://panax.io/source/request/value"
xover.spaces["source_filters"] = "http://panax.io/source/request/filters"
xover.spaces["source_fields"] = "http://panax.io/source/request/fields"
/* Values */
xover.spaces["exception"] = "http://panax.io/state/exception"
xover.spaces["confirmation"] = "http://panax.io/state/confirmation"
xover.spaces["readonly"] = "http://panax.io/state/readonly"
xover.spaces["suggested"] = "http://panax.io/state/suggested"
xover.spaces["initial"] = "http://panax.io/state/initial"
xover.spaces["search"] = "http://panax.io/state/search"
xover.spaces["filter"] = "http://panax.io/state/filter"
xover.spaces["prev"] = "http://panax.io/state/previous"
xover.spaces["fixed"] = "http://panax.io/state/fixed"
xover.spaces["text"] = "http://panax.io/state/text"
xover.spaces["env"] = "http://panax.io/state/environment"

xover.timeouts = new Map();

xover.alertManager = new Map();
xover.dom.alert = async function (message) {
    xover.alertManager[message] = xover.alertManager[message] || xover.delay(1).then(async () => {
        let xMessage = xover.data.createMessage(message)
        await xMessage.addStylesheet({ href: "message.xslt", role: "modal" });
        try {
            dom = await xMessage.transform();
            document.body && document.body.appendChild(dom.documentElement)
            return dom.documentElement;
        } catch (e) {
            console.error(e)
            return xover.dom.createDialog(typeof (message.cloneNode) != 'undefined' && message.cloneNode(true) || message)
        }
    }).finally(() => {
        delete xover.alertManager[message];
    })
    return xover.alertManager[message];
}

xover.dom.createDialog = function (message) {
    if (!message) { return null }
    let dialog_id = `dialog_${xover.cryptography.generateUUID()}`
    let dialog = document.querySelector(`#${dialog_id}`);
    if (!dialog) {
        let frag = window.document.createDocumentFragment();
        let p = window.document.createElement('p');
        p.innerHTML = `<dialog id="${dialog_id}" class="xover-component"><form method="dialog" onsubmit="closest('dialog').remove()"><section></section><menu><button type="submit">Close</button></menu></form></dialog>`;
        frag.append(...p.childNodes);
        window.document.body.appendChild(frag);
        dialog = document.querySelector(`#${dialog_id}`);
    }
    dialog.querySelector("section").innerHTML = '';
    if (message.documentElement instanceof HTMLElement) {
        let frag = window.document.createDocumentFragment();
        let p = window.document.createElement('p');
        p.innerHTML = message.documentElement.outerHTML;
        frag.append(...p.childNodes);
        message = frag;
    } else if ({}.constructor == message.constructor) {
        message = JSON.stringify(message);
    } else if (message instanceof Response) {
        message = message.statusText;
    }

    dialog.querySelector("section").append(message);
    document.querySelector(`#${dialog_id}`);
    dialog.showModal();
    return dialog;
}

Object.defineProperty(xover.session, 'updateSession', {
    value: async function (attribute, sync) {
        let session_variables;
        if (!attribute) {
            return;
        } else if (attribute.constructor == {}.constructor) {
            session_variables = new URLSearchParams(attribute);
        } /*else {
            session_variables = new URLSearchParams(`${attribute}=${value}`);
        }*/
        for (let pair of session_variables.entries()) {
            xover.session[pair[0]] = pair[1];
        }
        /*Se deshabilita la actualización por default*/
        if (sync && navigator.onLine && (xover.manifest.server || {})["session"] && await xover.session.status == 'authorized') {
            xover.post.to((xover.manifest.server || {})["session"], session_variables).catch(() => {
                console.log("Error al enviar sesión")
            })
        }
        return Promise.all([...session_variables.keys()].map((key) => xover.session[key]));
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.session, 'user_login', {
    get: function () {
        return xover.session.getKey("user_login")
    }
    , set: function (input) {
        if (xover.session.getKey("user_login") != input) {
            xover.session.id_token = undefined;
        }
    }
});

Object.defineProperty(xover.session, 'connection_id', {
    get: function () {
        return xover.session.getKey("store_id")
    }
    , set: function (input) {
        xover.session.store_id = input;
    }
});

//var __store_id_getter = function () { return xover.session.getKey("store_id") }  /*muestra de getter dinámico*/
Object.defineProperty(xover.session, 'store_id', {
    get: function () {
        return (xover.manifest.server && isFunction(xover.manifest.server.store_id) && xover.manifest.server.store_id() || xover.session.getKey("store_id") || xover.manifest.server.store_id)
    }
    , set: async function (input) {
        xover.dom.refreshTitle();
    }
});

Object.defineProperty(xover.session, 'cache_name', {
    get: function () {
        return xover.session.getKey("cache_name") || "";
    }
    , set() { }
});

xover.browser.isIE = function () {
    var ua = window.navigator.userAgent;
    return /MSIE|Trident/.test(ua) && !xover.browser.isEdge();
}

xover.browser.isEdge = function () {
    var ua = window.navigator.userAgent;
    return /Edge/.test(ua);
}

xover.browser.isSafari = function () {
    var ua = window.navigator.userAgent;
    return /Safari/.test(ua);
}

xover.browser.isIphone = function () {
    return navigator.userAgent.match(/iPhone/i);
}

xover.browser.isIPad = function () {
    return navigator.userAgent.match(/iPad/i);
}

xover.browser.isIOS = function () {
    return xover.browser.isIphone() || xover.browser.isIPad() || navigator.userAgent.match(/Macintosh/i);
}

Object.defineProperty(xover.debug, 'enabled', {
    get: function (ref) {
        return xover.session.debug;
    }
    , set: function (input) {
        xover.session.debug = !!input;
    }
});

var relative_path = (relative_path || "");

function getdate() { return autoCompleteDate("") }

function autoCompleteDate(sDate) {
    var pattern = /\b(\d{1,2})(?:(\/)(\d{1,2})(?:\2(\d{2,4}))?)?/
    var currentDate = new Date();
    var parts = (sDate.match(pattern) || []);
    var day = (parts[1] || currentDate.getDate())
    var month = (parts[3] || currentDate.getMonth() + 1)
    var year = (parts[4] || currentDate.getFullYear())
    var new_date = new Date(month + "/" + day + "/" + year)
    var new_string_date = new_date.toLocaleDateString("en-GB");
    var full_pattern = /\b(\d{1,2})(?:(\/)(\d{1,2})(?:\2(\d{2,4})))/
    if (new_string_date.match(full_pattern)) {
        sDate = new_string_date
    } else {
        new_string_date = day + "/" + month + "/" + year;
        if (new_string_date.match(full_pattern)) {
            sDate = new_string_date
        } else {
            sDate = '';
        }
    }
    return sDate;
}

function setDefaultDate(control) {
    if (!control) return;
    new_string_date = autoCompleteDate(control.value);
    var full_pattern = /\b(\d{1,2})(?:(\/)(\d{1,2})(?:\2(\d{2,4})))/
    if (new_string_date.match(full_pattern)) {
        control.value = new_string_date
    } else {
        control.value = '';
    }
    xover.data.update({
        target: control.id
        , attributes: [{ '@value': new_string_date }, { '@text': new_string_date }]
    });
    return new_string_date;
}

function isValidDate(date_string) {
    //var full_pattern = /\b(\d{1,2})(?:(\/)(\d{1,2})(?:\2(\d{2,4})))/
    //return (sDate.match(full_pattern) && Date.parse(sDate) != 'NaN');
    var date = new Date(date_string);
    return !isNaN(date.getTime());
}

function isValidISODate(sDate) {
    var full_pattern = /\b(\d{4})(?:(-)(\d{1,2})(?:\2(\d{1,2})))/
    return (sDate.match(full_pattern) && Date.parse(sDate) != 'NaN' && (new Date().getFullYear()) - (new Date(Date.parse(sDate)).getFullYear()) < 1000);
}

xover.dom.getGeneratedPageURL = function (config) {
    var html = config["html"];
    var css = config["css"];
    var js = config["js"];
    const getBlobURL = (code, type) => {
        const blob = new Blob([code], { type })
        return URL.createObjectURL(blob)
    }

    const cssURL = getBlobURL(css, 'text/css')
    const jsURL = getBlobURL(js, 'text/javascript')

    const source = `
    <html>
      <head>
        ${(css || "") && `<link rel="stylesheet" type="text/css" href="${cssURL}" />`}
        ${(js || "") && `<script defer="defer" src="${jsURL}"></script>`}
      </head>
      <body>
        ${html || ''}
      </body>
    </html>
  `
    return getBlobURL(source, 'text/html')
}

Object.defineProperty(xover.server, 'uploadFile', {
    value: async function (source, saveAs) {
        if (!(xover.manifest.server["uploadFile"])) {
            throw (new Error("Endpoint for uploadFile is not defined in the manifest"));
        }
        function uploadFile(file, source) {
            return new Promise((resolve, reject) => {
                let reader = new FileReader();
                reader.onload = function (e) {
                    var formData = new FormData();
                    formData.append(file.name, file);

                    let request = new xover.Request(xover.manifest.server["uploadFile"] + `?UploadID=${file.id}&saveAs=${file.saveAs}&parentFolder=${(file.parentFolder || '').replace(/\//g, '\\')}`, { method: 'POST', body: formData });
                    fetch(request).then(async response => {
                        let file_name = response.headers.get("File-Name") + `?name=${file.name.normalize()}`;
                        if (!file_name) throw (new Error("Cound't get file name"));
                        if (source && source instanceof Node) {
                            let temp_value = source.value;
                            //if (temp_value.match(/^blob:http:/)) {
                            if (source instanceof HTMLElement) {
                                if (!source.getAttribute("xo-attribute")) {
                                    source.setAttribute("xo-attribute", "x:value");
                                }
                                source = source.scope;
                                source.set(file_name)
                            }
                            //}
                            //[source, ...xover.stores.find(`//@*[starts-with(.,'blob:') and .='${temp_value}']`)].map(node => node instanceof Attr ? node.set(file_name) : node.setAttribute("value", file_name));
                        }
                        var progress_bar = document.getElementById('_progress_bar_' + file.id);
                        if (progress_bar) {
                            progress_bar.style.width = '100%';
                            progress_bar.className = progress_bar.className.replace(/\bbg-\w+/ig, 'bg-success');
                            progress_bar.className = progress_bar.className.replace(/\progress-bar-\w+/ig, '');
                        }
                        resolve(file_name);
                        //console.log(request.responseText)
                        //let res = new xover.Response(response, request);;
                        //let document = await res.processBody();
                        //console.log(document);
                    })
                    //request.onreadystatechange = function (oEvent) {
                    //    if (request.readyState === 4) {
                    //        delete xover.dom.intervals[file.id];
                    //        var progress_bar = document.getElementById('_progress_bar_' + file.id);
                    //        if (request.status === 200) {
                    //            if (source && source instanceof Node) {
                    //                source.selectSingleNode('..').setAttribute(source.name, `${file.parentFolder && '//' || ''}${file.saveAs}`)
                    //            }
                    //            if (progress_bar) {
                    //                progress_bar.style.width = '100%';
                    //                progress_bar.className = progress_bar.className.replace(/\bbg-\w+/ig, 'bg-success');
                    //                progress_bar.className = progress_bar.className.replace(/\progress-bar-\w+/ig, '');
                    //            }
                    //            //if (control.source) {
                    //            //    control.source.setAttribute('@value', control.value);
                    //            //    control.source.setAttribute('@state:progress', '100%');
                    //            //}
                    //            //console.log(request.responseText)
                    //        } else {
                    //            var message = request.statusText
                    //            if (progress_bar) {
                    //                progress_bar.style.width = '100%';
                    //                progress_bar.className = progress_bar.className.replace(/\bbg-\w+/ig, 'bg-danger');
                    //            }
                    //            switch (request.status) {
                    //                case 413:
                    //                    message = "El archivo es demasiado grande. Por favor suba un archivo más chico.";
                    //                    break;
                    //                default:
                    //                    message = request.statusText;
                    //            }
                    //            alert("Error " + request.status + ': ' + message);
                    //        }
                    //    }
                    //};
                    //request.send(formData);


                    ////xhr.post(formData);//e.target.result
                    ////xhr.post(e.target.result);
                    //try {
                    //    document.querySelector('#' + target).setAttribute('src', e.target.result);
                    //} catch (e) {
                    //    console.log(e.message)
                    //}
                    ////target.src=e.target.result;
                }
                reader.readAsDataURL(file);
            })
        }
        let files;
        let uploading = [];
        if (source instanceof HTMLElement && source.type === 'file') {
            file = source.files && source.files[0]
            if (!file) return;
            file.id = source.id;
            file.saveAs = saveAs || source.saveAs || file.id;
            uploading.push(uploadFile(file, source));
        } else if (source instanceof File) {
            file = source;
            file.id = file.id || source.id;
            file.saveAs = saveAs || file.saveAs || file.name;
            uploading.push(uploadFile(file, source));
        } else if (source instanceof Attr) {
            let files = source.value.split(/;/);
            for (let [ix, file_ref] of [...files.entries()]) {
                if (file_ref.indexOf("blob:") == -1) continue;
                let [file_name, searchParams] = file_ref.split("?");
                let record = await (await xover.storehouse.files).get(file_name);
                if (!(record && record.file)) {
                    return Promise.reject('Invalid file, upload again');
                }
                file = record.file;
                file.id = record.id;
                file.saveAs = saveAs || record.saveAs || file.id;
                /*let searchParameters = new URLSearchParams(Object.fromEntries(Object.entries({ file: record.file, id: record.id }), [...new URLSearchParams(searchParams.join("&")).entries()]));*/
                uploading.push(uploadFile(file, source).then(file_name => files[ix] = file_name).then(() => source.set(files.join(";"))));
            }
        }
        try {
            return Promise.all(uploading);
        } catch (e) {
            return Promise.reject("Couln't finish uploading files, please try again");
        }
    },
    writable: true, enumerable: false, configurable: false
})

function paddingDiff(col) {
    if (getStyleVal(col, 'box-sizing') == 'border-box') {
        return 0;
    }

    var padLeft = getStyleVal(col, 'padding-left');
    var padRight = getStyleVal(col, 'padding-right');
    return (parseInt(padLeft) + parseInt(padRight));
}

function getStyleVal(elm, css) {
    return (window.getComputedStyle(elm, null).getPropertyValue(css))
}

xover.data.updateScrollPosition = function (document, coordinates) {
    var target = coordinates.target;
    if (target) {
        Object.entries(coordinates).forEach(([key, value]) => {
            if (key != 'target' && target.source) {
                target.source.setAttributeNS(null, `state:${key}-position`, value);
                //var attributeRef = target.selectSingleNode(`//@state:${key}-position`);
                //if (attributeRef) {
                //    attributeRef.ownerElement.setAttributeNS(xover.spaces["state"], `state:${key}-position`, value, false);
                //}
            }
        })
    }
}

xover.dom.onscroll = function () {
    let element = this;
    xover.delay(500).then(async () => {
        let selector = this.selector;
        xover.site.get("scrollableElements", {})[selector] = xover.dom.getScrollPosition(element);
        history.replaceState(Object.assign({}, history.state), {}, location.pathname + location.search + (location.hash || ''));
    })
}

document.addEventListener("DOMContentLoaded", function (event) {
    //document.body.addEventListener('scroll', xover.dom.onscroll);
    //Object.values((xover.site.getScrollableElements() || {})).forEach(
    //    el => el.addEventListener('scroll', xover.dom.getScrollPosition)
    //);
    xover.evaluateParams()
});

xover.listener.on("render", function ({ dom }) {
    for (element of xover.site.getScrollableElements(dom)) {
        element.addEventListener('scroll', xover.dom.onscroll);
    }
});

window.addEventListener("focusin", function (event) {
    xover.site.save(event.target.selector);
});

window.addEventListener("input", function (event) {
    xover.site.save(event.target.selector);
});

document.addEventListener("selectionchange", function (event) {
    let target = document.getSelection().focusNode;
    if (target && target.nodeName == '#text') {
        xover.site.save(target.selector);
    }
});

var content_type = {}
content_type["json"] = "application/json";
content_type["xml"] = "text/xml";


//Object.defineProperty(xover.sources, 'reload', {
//    value: function (file_name_or_array, on_complete) {
//        Object.values(xover.stores).map(store => {
//            //(store.documentElement || document.createElement("p")).setAttributeNS(null, "state:refresh", true);
//            if (store.sources) {
//                store.sources = undefined;
//            }
//        });
//        var current_keys = xover.sources.cloneObject();

//        var file_name_or_array = (file_name_or_array || Object.keys(current_keys));
//        if (typeof (file_name_or_array) == 'string') {
//            file_name_or_array = [file_name_or_array];
//        }
//        for (let document_index = 0; document_index < file_name_or_array.length; document_index++) {
//            var file_name = file_name_or_array[document_index];
//            if (file_name in xover.sources) {
//                xover.sources[file_name] = undefined;
//            }
//        }
//        //var storage_enabled = xover.storage.enabled;
//        //if (storage_enabled) {
//        //    xover.storage.disable(file_name_or_array);
//        //}
//        xover.sources.load(file_name_or_array).then(response => {
//            if ((xover.manifest.server || {}).session) {
//                xover.session.checkStatus().then(() => xover.dom.refresh());
//            }
//        });
//        //xover.sources.load(file_name_or_array, (on_complete || function () {
//        //    xover.session.checkStatus().then(() => xover.dom.refresh());
//        //}));
//        //if (storage_enabled) {
//        //    xover.storage.enable();
//        //}
//    },
//    writable: true, enumerable: false
//});

//Object.defineProperty(xover.sources, 'reset', {
//    value: function (file_name_or_array) {
//        var _file_name_or_array = (file_name_or_array || Object.keys(xover.sources));
//        if (typeof (_file_name_or_array) == 'string') {
//            _file_name_or_array = [_file_name_or_array];
//        }
//        _file_name_or_array.map((file_name) => {
//            if (file_name in xover.sources) {
//                xover.sources[file_name] = undefined;
//            }
//        });
//    },
//    writable: true, enumerable: false
//});

Object.defineProperty(xover.sources, 'xover/normalize_namespaces.xslt', {
    get: function () {
        return xover.xml.createDocument(`
        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
          <xsl:output method="xml" indent="no" omit-xml-declaration="yes"/>
          <xsl:template match="@* | * | text() | processing-instruction() | comment()" priority="-1">
            <xsl:copy>
              <xsl:copy-of select="//namespace::*"/>
              <xsl:copy-of select="@*|*|text()"/>
            </xsl:copy>
          </xsl:template>
        </xsl:stylesheet>
        `)
    }
})

Object.defineProperty(xover.sources, 'xover/databind.xslt', {
    get: function () {
        return xover.xml.createDocument(`
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xo="http://panax.io/xover"
  xmlns:source="http://panax.io/source"
  xmlns:prev="http://panax.io/state/previous"
  xmlns:changed="http://panax.io/xover/binding/changed"
  xmlns:fetch="http://panax.io/fetch"
  xmlns:data="http://panax.io/fetch"
  xmlns:request="http://panax.io/fetch/request"
  xmlns:debug="http://panax.io/debug"
  xmlns:state="http://panax.io/state" version="1.0">
  <xsl:output method="xml" indent="no" omit-xml-declaration="yes"/>
  <xsl:key name="datasource" match="source:*" use="concat(generate-id(..),'::',local-name(),'::')"/>
  <xsl:key name="sourcedefinition" match="@source:*" use="concat(generate-id(..),'::',local-name(),'::')"/>

  <xsl:template match="@* | text() | processing-instruction() | comment()" priority="-1">
    <xsl:copy-of select="."/>
  </xsl:template>

  <xsl:template match="node()" priority="-1">
    <xsl:copy>
      <xsl:apply-templates select="@*"/>
      <xsl:apply-templates select="@source:*" mode="sources">
        <xsl:with-param name="mode">attributes</xsl:with-param>
      </xsl:apply-templates>
      <xsl:apply-templates select="@source:*" mode="sources">
        <xsl:with-param name="mode">nodes</xsl:with-param>
      </xsl:apply-templates>
      <xsl:apply-templates/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match="source:*/*/@xo:id" priority="-1"/>

  <xsl:template match="source:*[key('sourcedefinition',concat(generate-id(..),'::',local-name(),'::'))]"/>

  <xsl:template match="@source:*" mode="sources">
    <xsl:param name="ref" select=".."/>
    <xsl:param name="mode">nodes</xsl:param>
    <xsl:variable name="attribute_name" select="local-name()"/>
    <xsl:variable name="curr_value" select="../@xo:*[local-name()=$attribute_name and .!='' and .!='NULL']"/>
    <xsl:variable name="prev_value" select="../@prev:*[local-name()=$attribute_name]"/>
    <xsl:variable name="curr_source" select="../@source:*[local-name()=$attribute_name]"/>
    <xsl:variable name="prev_source" select="../@changed:*[local-name()=$attribute_name]"/>
    <xsl:variable name="current_datasource" select="key('datasource',concat(generate-id($ref),'::',local-name(),'::'))"/>
    <xsl:variable name="current_source_value">
      <xsl:choose>
        <xsl:when test="not(self::*)">
          <xsl:value-of select="."/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="../@*[local-name()=$attribute_name]"/>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="selected_record" select="$current_datasource/xo:r[@xo:*[local-name()=$attribute_name]=$curr_value]"/>
    <xsl:choose>
      <xsl:when test="$mode='attributes'">
        <!-- Sólo pueden ir atributos en esta sección -->
        <xsl:if test="$curr_value and not($current_datasource)">
          <xsl:attribute name="prev:{local-name()}">
            <xsl:value-of select="$curr_value"/>
          </xsl:attribute>
        </xsl:if>
        <!--<xsl:attribute name="debug:selected_record">
          <xsl:value-of select="$selected_record/@xo:id"/>
        </xsl:attribute>-->
        <xsl:copy-of select="$selected_record/@*[not(namespace-uri()='http://panax.io/xover' and local-name()='id')]"/>
        <xsl:choose>
          <xsl:when test="$current_datasource and not($current_datasource[@command=$curr_source]) or contains($curr_source,'{{') and $curr_value">
            <xsl:if test="$curr_value">
              <xsl:attribute name="xo:{local-name()}"></xsl:attribute>
              <xsl:attribute name="prev:{local-name()}">
                <xsl:value-of select="$curr_value"/>
              </xsl:attribute>
            </xsl:if>
            <xsl:attribute name="changed:{local-name()}">
              <xsl:value-of select="$curr_source"/>
            </xsl:attribute>
            <xsl:attribute name="state:refresh">true</xsl:attribute>
          </xsl:when>
        </xsl:choose>
      </xsl:when>
      <xsl:when test="$mode='nodes'">
        <!-- Sólo pueden ir nodos en esta sección -->
        <xsl:choose>
          <xsl:when test="contains($curr_source,'{{')"></xsl:when>
          <xsl:when test="$current_datasource[@command=$curr_source]">
            <xsl:copy-of select="($current_datasource[@command=$curr_source])[1]"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:element name="{name()}" namespace="{namespace-uri()}">
              <xsl:attribute name="xo:id">
                <xsl:value-of select="concat('__request_',generate-id())"/>
              </xsl:attribute>
              <xsl:attribute name="changed:{local-name()}"></xsl:attribute>
              <xsl:attribute name="command">
                <xsl:value-of select="$curr_source"/>
              </xsl:attribute>
              <!--<xsl:if test="$curr_value">
                <xsl:element name="xo:r">
                  <xsl:attribute name="xo:{local-name()}">
                    <xsl:value-of select="$curr_value"/>
                  </xsl:attribute>
                </xsl:element>
              </xsl:if>-->
            </xsl:element>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="@source:init[.='true']">
  </xsl:template>

  <xsl:template match="@source:init[.='true']" mode="sources">
  </xsl:template>

  <xsl:template match="@changed:*">
  </xsl:template>
</xsl:stylesheet>`);
    }
})

Object.defineProperty(xover.stores, '#', {
    get: function () {
        return xover.manifest.sources["#"] && (this[xover.manifest.sources["#"]] || new xover.Store(xover.sources["#"], { tag: xover.manifest.sources["#"] })); //new xover.Store(xover.manifest.sources["#"] && xover.sources["#"] || xover.sources["#shell"], { tag: "#" });//
    }
});

Object.defineProperty(xover.stores, 'active', {
    get: function () {
        let store = xover.stores[xover.site.active] || xover.stores[xover.site.seed] || xover.stores["#"];// || xover.Store(`<?xml-stylesheet type="text/xsl" href="message.xslt" role="modal" target="body" action="append"?><xo:message xmlns:xo="http://panax.io/xover" xo:id="xhr_message_${Math.random()}"/>`);
        return store;
    }
    , set: async function (input) {
        if (input && typeof input.then == 'function') {
            input = await input;
        }
        if (!(input instanceof xover.Store)) {
            input = new xover.Store(input);
            //input.reseed();
        }

        if (input) {
            var hashtag = input.tag;// || xover.data.hashTagName(input);
            if (hashtag === xover.stores.active.tag) {
                var current_position = xover.data.getScrollPosition();
                xover.data.updateScrollPosition(input, current_position);
            }

            xover.stores[hashtag] = input;
            //if (hashtag != (history.state.seed || (window.top || window).location.hash || xover.stores["#"].tag)) {//(history.state.hash || (window.top || window).location.hash)
            if (!xover.stores[hashtag].isActive) {
                //xover.dom.history.push((window.top || window).location.hash);
                xover.site.active = hashtag;
            }
            /*await */xover.stores[hashtag].render();
        }
    }
});

Object.defineProperty(xover.stores, 'find', {
    value: function (ref) {
        var return_array = [];

        var target = xover.stores.active.find(ref);
        if (target) {
            //return_array.push([target, xover.stores.active]);
            return_array.push(target);
        }
        //xover.stores.filter((nombre, document) => document.selectSingleNode(`//*[@xo:id="${typeof (ref) == 'string' ? ref : ref.getAttributeNS("http://panax.io/xover", "id")}"]`))
        for (let xDocument in xover.stores) {
            target = xover.stores[xDocument].find(ref);
            if (target) {
                //return_array.push([target, xover.stores[xDocument]]);
                return_array.push(target);
            }
        }
        //Object.entries(sessionStorage).filter(([key]) => key.match(/^#/) && !xover.stores.hasOwnProperty(key)).map(([hashtag, value]) => {
        //    let restored_document = xover.session.getKey(hashtag)
        //    if (restored_document) {
        //        restored_document = new xover.Store(new xover.Source(restored_document.source).document, { tag: hashtag });
        //        if (restored_document.find(ref)) {
        //            return_array.push(xover.stores[hashtag].find(ref));
        //        }
        //    }
        //})
        return_array = [...new Set(return_array)];
        return new xover.NodeSet(return_array);
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.stores, 'getActive', {
    value: function (attribute, value) {
        let active = Object.entries(xover.stores).reduce((json, [tag, store]) => {
            if (store && store.isActive) {
                json[tag] = store;
            };
            return json;
        }, {});

        Object.defineProperty(active, 'getInitiators', {
            value: function () {
                return Object.values(active).reduce((arr, item) => {
                    if (item.initiator) {
                        arr.push(item.initiator);
                    };
                    return arr;
                }, []);
            },
            writable: false, enumerable: false, configurable: false
        });
        return active;
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.stores, 'getInactive', {
    value: function (attribute, value) {
        return Object.entries(xover.stores).reduce((json, item) => { if (!(item[1].isActive)) { json[item[0]] = item[1]; }; return json }, {});
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.stores, 'clear', {
    value: function (attribute, value) {
        Object.keys(this).map(key => delete this[key]);
        sessionStorage.clear();
        return this;
    },
    writable: false, enumerable: false, configurable: false
});

const original_removeAttribute = Element.prototype.removeAttribute;
const original_remove = Element.prototype.remove;
const replaceChild_original = Element.prototype.replaceChild
const original_setAttribute = Element.prototype.setAttribute;
const original_setAttributeNS = Element.prototype.setAttributeNS;
const original_setAttributeNodeNS = Element.prototype.setAttributeNodeNS;
Object.defineProperty(xover.stores, 'restore', {
    value: async function (name_list = []) {
        name_list = name_list instanceof Array && name_list || [name_list];
        let restoring = [];
        if (xover.session.disableCache) return;

        //Object.entries(sessionStorage).filter(([key]) => key != '#' && (!name_list.length || name_list.includes(key)) && key.match(/^#/)).forEach(([tag, value]) => {
        //    console.log('Restoring document ' + tag);
        //    xover.stores[tag] = new xover.Store(xover.sources[JSON.parse(value)["source"]], { tag: tag });
        //})
        return restoring;
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.stores, 'seed', {
    get: function () {
        return this[xover.site.seed] || this["#"];
    }
});

xover.NodeSet = function (nodeSet = []) {
    if (!(this instanceof xover.NodeSet)) return new xover.NodeSet(nodeSet);
    Object.defineProperty(nodeSet, 'remove', {
        value: function (refresh) {
            nodeSet.removeAll(refresh);
            return nodeSet;
            //var stores = [];
            //for (let i = nodeSet.length - 1; i >= 0; --i) {
            //    var target = nodeSet.pop();
            //    if (refresh !== false && target.ownerDocument.store && !stores.find(store => store === target.ownerDocument.store)) {
            //        stores.push(target.ownerDocument.store)
            //    }
            //    if (target.nodeType == 2/*attribute*/) {
            //        //var attribute_name = target.name;
            //        var ownerElement = target.ownerElement;
            //        if (ownerElement) {
            //            target.remove(); //original_removeAttribute.apply(ownerElement, [attribute_name]);
            //            //ownerElement.removeAttribute(attribute_name, refresh);
            //        }
            //    } else {
            //        refresh = [refresh, true].coalesce();
            //        target.remove(); //original_remove.apply(target, arguments);
            //        //target.remove(refresh);
            //        //target.parentNode.removeChild(target); //Se cambió el método por remove para que sea responsivo
            //    }
            //}
            ////stores.map(store => store.render(refresh));
        },
        writable: true, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'setAttribute', {
        value: function (attribute, value, refresh) {
            //attribute = attribute.replace(/^@/, "");
            nodeSet.map((target) => {
                if (target instanceof Element || target.nodeType == 1) {
                    target.setAttribute(attribute, value, refresh);
                }
            });
        },
        writable: true, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'set', {
        value: async function (...args) {
            nodeSet.forEach((target) => {
                target.set.apply(target, args);
            });
        },
        writable: true, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'setAttributeNS', {
        value: async function (namespaceURI, attribute, value, refresh) {
            //attribute = attribute.replace(/^@/, "");
            nodeSet.map((target) => {
                if (target instanceof Element || target.nodeType == 1) {
                    target.setAttributeNS(namespaceURI, attribute, value, refresh);
                }
            });
        },
        writable: true, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'getAttribute', {
        value: function (attribute) {
            //attribute = attribute.replace(/^@/, "");
            return nodeSet.reduce((arr, item) => { arr.push(item.getAttribute(attribute)); return arr; }, []);
        },
        writable: true, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'highlight', {
        value: function () {
            nodeSet.map(node => { [...document.querySelectorAll(`#${node.getAttributeNS("http://panax.io/xover", "id")},[xo-source='${node.getAttributeNS("http://panax.io/xover", "id")}']`)].map(target => target.style.outline = '#f00 solid 2px') })
        },
        writable: true, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'setAttributes', {
        value: async function (delay) {
            if (!isNaN(parseInt(delay))) {
                await xover.delay(delay);
            }
            return new Promise((resolve, reject) => {
                nodeSet.map(target => {
                    if (target instanceof Element || target.nodeType == 1) {
                        target.setAttributes.apply(target, arguments).then(() => resolve(true));
                    }
                });
            });
        },
        writable: true, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'removeAttribute', {
        value: function (attribute, refresh, delay) {
            //attribute = attribute.replace(/^@/, "");
            var stores = [];
            nodeSet.map((target) => {
                if (target.ownerDocument.store && !stores.find(store => store === target.ownerDocument.store)) {
                    stores.push(target.ownerDocument.store)
                }
                if (target instanceof Element || target.nodeType == 1) {
                    refresh = [refresh, true].coalesce();
                    original_removeAttribute.apply(target, [attribute]);
                }
            });
            stores.map(store => store.render(refresh));
        },
        writable: true, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'appendBefore', {
        value: function () {
            nodeSet.map(target => {
                if (target instanceof Element || target.nodeType == 1) {
                    target.appendBefore.apply(target, arguments);
                }
            });
        },
        writable: true, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'appendAfter', {
        value: function () {
            nodeSet.map(target => {
                if (target instanceof Element || target.nodeType == 1) {
                    target.appendAfter.apply(target, arguments);
                }
            });
        },
        writable: true, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'textContent', {
        value: function () {
            nodeSet.map(target => {
                if (target instanceof Element || target.nodeType == 1) {
                    target.textContent.apply(target, arguments, false);
                }
            });
        },
        writable: true, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'moveTo', {
        value: function () {
            nodeSet.map(target => {
                if (target instanceof Element || target.nodeType == 1) {
                    target.moveTo.apply(target, arguments);
                }
            });
        },
        writable: true, enumerable: false, configurable: false
    });
    Object.setPrototypeOf(nodeSet, this);
    Object.setPrototypeOf(nodeSet, Array.prototype);
    return nodeSet;
}

xover.xml.createFromActiveX = function () {
    if (typeof arguments.callee.activeXString != "string") {
        var versions = ["MSXML2.DOMDocument"];

        for (let i = 0, len = versions.length; i < len; i++) {
            try {
                var xmldom = new ActiveXObject(versions[i]);
                arguments.callee.activeXString = versions[i];
                return xmldom;
            } catch (ex) {
                //skip
            }
        }
    }
    return new ActiveXObject(arguments.callee.activeXString);
}

xover.xml.getNamespaces = function () {
    var namespaces = {};
    for (let a = 0; a < arguments.length; ++a) {
        if (!arguments[a]) {
            continue;
        }
        if (arguments[a].getNamespaces) {
            namespaces.merge(arguments[a].getNamespaces())
        } else if (typeof (arguments[a].selectSingleNode) != 'undefined') {
            var sXML = (arguments[a].document || arguments[a]).toString();
            if (sXML) {
                if (sXML.match(/\bxml:/)) {
                    namespaces["xml"] = "http://www.w3.org/XML/1998/namespace";
                }
                namespaces.merge(JSON.parse('{' + (sXML.match(/(xmlns:\w+)=(["'])([^\2]+?)\2/ig) || []).join(", ").replace(/xmlns:(\w+)=(["'])([^\2]+?)\2/ig, '"$1":$2$3$2') + '}'));
            }
        }
    }
    return namespaces;
}

xover.xml.setNamespaces = function (xml_document, namespaces) {
    Object.entries(namespaces).forEach(ns => {
        xml_document.setAttribute(ns[0], ns[1], false);
    })
    return xml_document;
}

xover.xml.createNamespaceDeclaration = function () {
    var namespaces = xover.xml.getNamespaces.apply(this, arguments);
    return Object.entries(namespaces).map(([key, value]) => `xmlns:${key}="${value}"`).join(" ");
}

xover.Response = function (response, request) {
    if (!(this instanceof xover.Response)) return new xover.Response(response);
    let _original = response.clone();
    let file_name = new URL(request.url).pathname.replace(new RegExp(location.pathname.replace(/[^/]+$/, "")), "");
    if (response.status == 404) {
        if (file_name in xover.sources.defaults) {
            response = new Response(xover.sources.defaults[file_name], { headers: { "Content-type": "text/xsl" } })
        }/* else if (request.settings.tag in xover.sources.defaults) {
            response = new Response(xover.sources.defaults[request.settings.tag], { headers: { "Content-type": "text/xml" } })
        }*/
    }
    let self = this;
    Object.defineProperty(self, 'originalResponse', {
        get: function () {
            return _original.clone();
        }
    });
    Object.defineProperty(self, 'request', {
        get: function () {
            return request;
        }
    });
    Object.defineProperty(self, 'render', {
        value: function ({ to, stylesheet } = {}) {
            //let content = response.json ? JSON.stringify(response.json) : response.document.body.innerHTML;
            //if (response.ok) {
            //    if (typeof (to) == 'function') {
            //        try {
            //            to.apply(to, [content])
            //        } catch (e) {
            //            if (e.message == 'Illegal invocation') {
            //                to.call(window, content);
            //            }
            //        }
            //    } else if (to) {
            //        to.innerHTML = content;
            //    } else {
            //        xover.dom.createDialog(content);
            //    }
            //} else {
            let response = this.json || this.document || this.body || `${this.statusText}: ${file_name}`;
            response.render && response.render();
            //}
        }
    });
    Object.defineProperty(self, 'processBody', {
        value: async function () {
            //if (request && request.initiator) {
            //    window.document.querySelectorAll(`[xo-store="${request.initiator.tag}"] .working`).forEach(el => el.classList.remove('working'));
            //    request.initiator.state.loading = undefined;
            //}

            let body = undefined;
            let charset = {}.merge(
                Object.fromEntries([...new URLSearchParams((request.headers.get('Accept') || '').toLowerCase().replace(/;\s*/g, '&'))])
                , Object.fromEntries([...new URLSearchParams((response.headers.get('Content-Type') || '').toLowerCase().replace(/;\s*/g, '&'))])
            )["charset"] || '';
            let contentType = response.headers.get('Content-Type') || '*/*';


            var responseText;
            if (charset.indexOf("iso-8859-1") != -1) {
                await response.arrayBuffer().then(buffer => {
                    let decoder = new TextDecoder("iso-8859-1");
                    let text = decoder.decode(buffer);
                    responseText = text;
                }).catch(error => Promise.reject(error));
            } else {
                if (contentType.toLowerCase().indexOf("manifest") != -1 || (request.url.href || '').match(/(\.manifest|\.json)$/i)) {
                    //await response.json().then(json => body = json);
                    await response.text().then(text => body = text);
                    responseText = body;
                } else if (contentType.toLowerCase().indexOf("json") != -1) {
                    body = await response.json();
                    responseText = JSON.stringify(body);
                } else {
                    body = await response.text();
                    if (body.substr(0, 2) === '��') { //Removes BOM mark
                        body = body.replace(/\x00/ig, '');
                        body = body.substr(2);
                    }
                    responseText = body;
                }
            }

            Object.defineProperty(response, 'responseText', {
                get: function () {
                    return responseText;
                }
            });

            let _body_type;
            Object.defineProperty(response, 'bodyType', {
                get: function () {
                    let contentType = response.headers.get('Content-Type') || '*/*';
                    if (_body_type) {
                        return _body_type;
                    } else if (contentType.toLowerCase().indexOf("html") != -1) {
                        return "html";
                    } else if ((contentType.toLowerCase().indexOf("json") != -1 || contentType.toLowerCase().indexOf("manifest") != -1 || (request.url.href || '').match(/(\.manifest|\.json)$/i)) && xover.json.isValid(xover.json.tryParse(responseText))) {
                        return "json";
                    } else if ((contentType.toLowerCase().indexOf("xml") != -1 || contentType.toLowerCase().indexOf("xsl") != -1 || body.toLowerCase().indexOf("<?xml ") != -1 || contentType.toLowerCase().indexOf('application/octet-stream') != -1) && xover.xml.isValid(xover.xml.tryParse(responseText))) {
                        return "xml"
                    } else {
                        return "text";
                    }
                }, set: function (input) {
                    _body_type = input;
                }
            });

            switch (response.bodyType) {
                case "html":
                    var parser = new DOMParser();
                    body = parser.parseFromString(responseText, 'text/html');
                    //var frag = window.document.createDocumentFragment(); //make your fragment
                    //var p = window.document.createElement('p'); //create <p>test</p> DOM node
                    //p.innerHTML = responseText;
                    //frag.append(...p.childNodes);
                    //body = frag;
                    Object.defineProperty(response, 'json', {
                        value: null
                    });
                    Object.defineProperty(response, 'html', {
                        get: function () {
                            return body;
                        }
                    });
                    break;
                case "xml":
                    body = xover.xml.createDocument(responseText, { autotransform: false });
                    Object.defineProperty(response, 'json', {
                        value: null
                    });
                    Object.defineProperty(response, 'xml', {
                        get: function () {
                            return body;
                        }
                    });
                    break;
                case "json":
                case "manifest":
                    body = xover.json.tryParse(responseText);
                    Object.defineProperty(response, 'json', {
                        get: function () {
                            return body;
                        }
                    });
                    if ((request.headers.get('Accept') || '').toLowerCase().indexOf("xml") != -1) {
                        try {
                            body = xover.xml.fromJSON(body);
                            Object.defineProperty(response, 'xml', {
                                get: function () {
                                    return body;
                                }
                            });
                            _body_type = 'xml';
                        } catch (e) {
                            console.warn(e);
                        }
                    }
                    break;
                default:
                    body = responseText;
                    Object.defineProperty(response, 'json', {
                        value: null
                    });
            }

            if (body instanceof Document) {
                Object.defineProperty(response, 'document', {
                    get: function () {
                        return body;
                    }
                });
                let __document = body;
                for (let prop of ['$', '$$', 'cloneNode', 'normalizeNamespaces', 'contains', 'querySelector', 'querySelectorAll', 'selectSingleNode', 'selectNodes', 'select', 'selectFirst', 'evaluate', 'getStylesheets', 'createProcessingInstruction', 'firstElementChild', 'insertBefore', 'resolveNS']) {
                    let prop_desc = Object.getPropertyDescriptor(__document, prop);
                    if (!prop_desc) {
                        continue
                    } else if (prop_desc.value) {
                        Object.defineProperty(this, prop, {
                            value: function () { return __document[prop].apply(__document, arguments) }
                            , enumerable: true, configurable: false
                        });
                    } else if (prop_desc.get) {
                        Object.defineProperty(this, prop, {
                            get: function () { return __document[prop] }
                            , enumerable: true, configurable: false
                        });
                    }
                }
            }

            if (body.documentElement) {
                Object.defineProperty(response, 'documentElement', {
                    get: function () {
                        return body.documentElement;
                    }
                });
            }

            Object.defineProperty(response, 'body', {
                get: function () {
                    return body;
                }
            });

            return body;
        }
    });
    Object.setPrototypeOf(response, this);
    return response;
}
xover.Response.prototype = Object.create(Response.prototype);

var original_href = Object.getOwnPropertyDescriptor(URL.prototype, 'href');
xover.URL = function (url, base, settings = {}) {
    if (url === null) {
        return Promise.reject(`${url} is not a valid value for xover.URL`)
    }
    if (!(this instanceof xover.URL)) return new xover.URL(url, base, settings);

    let method;
    if (!(url instanceof URL)) {
        url = url || '';
        [, method, url] = (url.toString() || '').match(/^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)?(.*)/);
        if (settings["payload"] instanceof Document) {
            settings["body"] = settings["payload"];
            delete settings["payload"];
        }
        method = settings["method"] || method;
        url = new URL(url.trim()/*.replace(/\+/g, '%2B').replace(/\s/g, '%20')*/, base || location.origin + location.pathname.replace(/[^/]+$/, ""));
        if (!method && settings["body"]) {
            method = 'POST'
        }
    }
    let query = new URLSearchParams(settings["query"] || settings["payload"] || {});
    [...query.entries()].forEach(([key, value]) => url.searchParams.append(key, value));
    delete settings["query"];
    delete settings["payload"];

    url.settings = url.settings || {};
    url.settings.method = method || url.settings.method;
    url.settings.merge(settings);
    url.settings.headers = new Headers(url.settings.headers || {});

    [...new Headers(settings["headers"] || {}).entries()].forEach(([key, value]) => {
        if (value) {
            url.settings.headers.set(key, value);
        }
    });
    [...url.searchParams.entries()].filter(([key]) => key[0].indexOf("^") == 0).forEach(([key, value]) => {
        if (value) {
            url.settings.headers.set(key, value);
        }
        url.searchParams.delete(key)
    });
    if (!url.hasOwnProperty('method')) {
        Object.defineProperty(url, 'method', {
            get: function () {
                return method;
            }, set: function (input) {
                return method = input;
            }
        })
    }
    Object.setPrototypeOf(url, URL.prototype);
    return url;
}

Object.defineProperty(URL.prototype, 'href', {
    get: function (...args) {
        let href = original_href.get.apply(this, args);
        return href.replace(new RegExp(`^${location.origin}`), "").replace(new RegExp(`^${location.pathname.replace(/[^/]+$/, "")}`), "")//.replace(/^\/+/, '');
    }
});

xover.QUERI = function (href) {
    function encodeValue(value) {
        if (!value) return value;
        value = value.replace(/%/, '%25');
        return value
    }
    class Predicate extends URLSearchParams {
        constructor(queryString) {
            super(queryString);
        }
        append(name, value) {
            value = encodeValue(value);
            if (value === undefined) {
                url.searchParams.delete(name)
            } else {
                url.searchParams.append(name, value)
            }
        }
        set(name, value) {
            value = encodeValue(value);
            url.searchParams.set(name, value)
        }
        delete(name) {
            url.searchParams.delete(name)
        }
    };
    class Fields {
        constructor(json) {
            let proxy = new Proxy(json, {
                get(self, key) {
                    if (self.hasOwnProperty(key)) {
                        return self[key];
                    }
                    return undefined; // or delegate to another object
                }, set(self, key, value) {
                    if (value === undefined) {
                        delete self[key];
                    } else {
                        self[key] = value;
                    }
                    headers.set("fields", new URLSearchParams(Object.entries(self)))
                    url.hash = `#${new URLSearchParams(headers.entries()).toString()}`
                }, deleteProperty: function (self, key) {
                    delete self[key];
                    url.hash = `#${new URLSearchParams(headers.entries()).toString()}`
                }
            });

            Object.defineProperties(proxy, {
                toString: {
                    value: function () {
                        return new URLSearchParams(this).toString()
                    }, enumerable: false, writable: false, configurable: false
                }
            });
            return proxy
        }
    }


    if (!(this instanceof xover.QUERI)) return new xover.QUERI(href);
    let ref = href;
    let fields, schema, name, mode, identity_value, primary_values, ref_node, settings = new URLSearchParams();
    href = (href instanceof Attr ? href.value : href);

    let getParts = function (key) {
        let pathname = url.pathname.replace(/^\//, '');
        [pathname, mode] = pathname.split(/~/);
        [pathname, identity_value] = pathname.split(/:/);
        [pathname, ref_node] = pathname.split(/@/);
        [schema = '', name = '', ...primary_values] = pathname.split(/\//);
        return { schema, name, mode, primary_values, identity_value, ref_node }
    }
    let url = xover.URL(href);
    if (!(url instanceof URL)) {
        if (url instanceof Promise)
            return url
        else
            return Promise.reject(`${href} is not a valid value for QUERI`)
    }
    let predicate = new Predicate(url.searchParams);
    let headers = new Headers(new URLSearchParams(url.hash.replace(/^[\?#]+/, '')));
    parts = getParts();
    let target = new Proxy({}, {
        get: function (self, key) {
            if (parts.hasOwnProperty(key)) {
                return parts[key];
            }
            if (self.hasOwnProperty(key)) {
                return self[key];
            }
            return url[key];
        },
        set: function (self, key, value) {
            self[key] = value;
            if (key in url) {
                url[key] = value;
            }
            parts = getParts();
        }
    });

    Object.defineProperties(target, {
        fields: {
            get: function () {
                let fields = Object.fromEntries(new URLSearchParams((headers.get("fields") || '').replace(/\+/g, '%2B')).entries());
                return new Fields(fields);
            },
            set: function (input) {
                headers.set("fields", input);
                parts = getParts();
            }
        },
        predicate: {
            get: function () {
                return new Predicate(url.searchParams);
            },
            set: function (input) {
                url.search = input;
            }
        },
        headers: {
            get: function () {
                return headers;
            }
        }, toString: {
            value: function () {
                return `${url.pathname}?${url.searchParams.toString()}#${new URLSearchParams(headers.entries()).toString()}`;
            }, enumerable: false, writable: false, configurable: false
        }, update: {
            value: function () {
                if (ref instanceof Node) {
                    ref.updateManager = ref.updateManager || xover.delay(1).then(async () => {
                        ref.value = this.toString();
                        delete ref.updateManager;
                    })
                }
            }, enumerable: false, writable: false, configurable: false
        }
    });

    Object.defineProperties(target, {
        assign: {
            value: function (attribs) {
                target.merge(attribs);
                if (ref instanceof Node) {
                    ref.set(target.toString());
                } else {
                    ref = target.toString();
                }
                return ref;
            }, enumerable: false, writable: false, configurable: false
        }
    });
    return target;
}

xover.qri = xover.QUERI;
xover.QRI = xover.qri;

xover.Request = function (request, settings = {}) {
    if (!(this instanceof xover.Request)) return new xover.Request(request, settings);
    settings.merge(request.settings);
    let url, req;
    let self = this;
    let _request = request;
    if (request instanceof Request) {
        req = request;
        if (Object.keys(settings).length) {
            let { method, headers, mode, credentials, cache, redirect, referrer, integrity } = req;
            let url = new xover.URL(req.url, location.origin + location.pathname.replace(/[^/]+$/, ""), settings);
            req = new Request(url, Object.assign({ method, headers, mode, credentials, cache, redirect, referrer, integrity }, { body: settings.body }));
        }
    } else {
        let headers;
        if (request instanceof URL) {
            url = new xover.URL(request, undefined, settings);
        } else if (request.constructor == {}.constructor) {
            url = new xover.URL(url, undefined, settings);
        } else {
            url = new xover.URL(request, undefined, settings);
        }
        let fileExtension = url.pathname.substring(url.pathname.lastIndexOf('.') + 1);
        headers = new Headers();
        if (settings["headers"] instanceof Headers) {
            for (let key of Object.keys(Object.fromEntries(settings["headers"].entries()))) {
                headers.set(key, settings["headers"].get(key));
            }
        }
        for (let key of Object.keys(settings["headers"] || {})) {
            headers.set(key, settings["headers"][key]);
        }
        headers.set("Accept", (headers.get("Accept") || xover.mimeTypes[fileExtension] || '*/*'));
        settings["method"] = url.method || request.method;
        settings = xover.json.merge(settings, {
            headers: headers
        });
        req = new Request(url, settings);
    }
    if (req.method == 'POST' && ((event || {}).srcElement || {}).closest) {
        let form = event.srcElement.closest('form');
        if (form && !form.getAttribute('action')) {
            form.setAttributeNS(null, 'action', 'javascript:void(0);'); //Esto corrige comportamiento indeseado en los post cuando el formulario no tiene action
        }
    }

    //var srcElement = event && event.target;
    //if (srcElement instanceof HTMLElement) {
    //    let initiator_button = srcElement.closest('button, .btn')
    //    initiator_button && initiator_button.classList.add("working");
    //    //if (event && event.target && event.target.store && event.target.store.documentElement.selectSingleNode('self::xo:prompt')) { //TODO: Cambiar el método para identificar el initiator
    //    //    req.initiator = event && event.target && event.target.store;
    //    //}
    //}
    //if (req.initiator) {
    //    req.initiator.state.loading = true;
    //}
    Object.defineProperty(self, 'url', {
        get: function () {
            return url;
        }
    })
    //Object.defineProperty(self, 'initiator', {
    //    get: function () {
    //        return _request.initiator;
    //    }
    //})
    Object.defineProperty(self, 'settings', {
        value: settings
    })
    Object.defineProperty(self, 'parameters', {
        get: function () {
            return Object.fromEntries(new URL(url).searchParams.entries());
        }
    })
    Object.defineProperty(self, 'body', {
        get: function () {
            return url.body;
        }
    })
    Object.setPrototypeOf(req, this);
    return req;
}
xover.Request.prototype = Object.create(Request.prototype);

xover.fetch = async function (url, ...args) {
    let endIndex = args.length - 1;
    while (endIndex >= 0 && (args[endIndex] === undefined)) {
        endIndex--;
    }
    args.splice(endIndex + 1);
    let tag = (url.pathname || url || '');
    let handlers = [];
    for (let i = args.length - 1; i >= 0; --i) {
        if (typeof (args[i]) == 'function') {
            handlers.push(args[i]);
            args.splice(i, 1)
        }
    }
    let settings = args.pop() || {};
    settings.merge(Object.fromEntries(xo.manifest.getSettings(tag)));
    url = new xover.URL(url, undefined, settings);

    for (let i = args.length - 1; i >= 0; --i) {
        if (args[i] instanceof Headers) {
            let header = args[i];
            for (let [key, value] of [...header.entries()]) {
                url.settings.headers.set(key, value);
            }
            args.splice(i, 1)
        }
    }

    for (let i = args.length - 1; i >= 0; --i) {
        if (args[i] instanceof URLSearchParams) {
            let searchParams = args[i];
            for (let [key, value] of [...searchParams.entries()]) {
                url.searchParams.append(key, value);
            }
            args.splice(i, 1)
        }
    }

    let payload = args.pop();
    if (payload) {
        if (url.method === 'POST' || payload instanceof Document) {
            url.method = 'POST';
            url.body = payload;
        } else {
            for (let [key, value] of [...new URLSearchParams(payload).entries()]) {
                url.searchParams.append(key, value);
            }
        }
    }
    payload = url.body;
    if (payload) {
        settings["method"] = 'POST';
        let pending = [];
        if (payload instanceof XMLDocument) {
            payload.$$(".//@*[starts-with(.,'blob:')]").filter(node => node && (!node.namespaceURI || node.namespaceURI.indexOf('http://panax.io/state') == -1)).map(node => { pending.push(xover.server.uploadFile(node)) })
        }
        await Promise.all(pending);
    }

    if (settings.progress instanceof HTMLElement) {
        settings.progress.value = 0;
    }
    //settings.headers = new Headers(Object.fromEntries([...new Headers(this instanceof xover.Source && this.headers || {}), ...new Headers(this instanceof xover.Source && (this.settings || {}).headers || {}), ...new Headers(settings.headers)]));
    let request = new xover.Request(url, settings);
    var original_response;
    const controller = new AbortController();
    const signal = controller.signal;
    try {
        original_response = await fetch(request.clone(), { signal })
    } catch (e) {
        try {
            if (!original_response && request.method == 'POST') {
                const body = await request.clone().text();
                const { cache, credentials, headers, integrity, mode, redirect, referrer } = request;
                const init = { body, cache, credentials, headers, integrity, mode, redirect, referrer };
                original_response = await fetch(request.url, init);
            }
        } catch (e) {
            return Promise.reject([e, request, { bodyType: 'text' }]);
        }
    }

    if (this !== xover.server) {
        this.controller = controller;
    }
    //let source = settings["source"] instanceof xover.Source && settings["source"] || this instanceof xover.Source && this || undefined;
    let res = original_response.clone();
    const contentLength = res.headers.get('content-length');
    let receivedLength = 0;
    const stream = res.body.getReader();
    const progress = () => {
        stream.read().then(({ done, value }) => {
            let _progress;
            //source.abortFetch = null;
            if (done) {
                _progress = 100;
            } else {
                receivedLength += value.byteLength;
                let percent = (receivedLength / contentLength) * 100
                _progress = percent;
                progress();
            }
            window.top.dispatchEvent(new xover.listener.Event('progress', { controller, percent: _progress }, request));
        }).catch(e => {
            console.log(e)
        });
    };
    progress();
    if (!original_response) return Promise.reject(`No response for ${url}!`);
    let response = new xover.Response(original_response, request);
    let document = await response.processBody();

    if (document instanceof Document) {
        let url = request.url;
        let href = url.href.replace(new RegExp(`^${location.origin}`), "").replace(new RegExp(`^${location.pathname.replace(/[^/]+$/, "")}`), "").replace(/^\/+/, '');
        Object.defineProperty(document, 'url', {
            get: function () {
                return url;
            }
        });
        Object.defineProperty(document, 'href', {
            get: function () {
                return href
            }
        });
    }
    let self = this;
    if (this instanceof xover.Source) {
        Object.defineProperty(document, 'source', {
            get: function () {
                return self;
            }
        });
    }
    response.tag = '#' + ((`${url.pathname || url}`).replace(/^\//, ''));
    let manifest_settings = xover.manifest.getSettings(response.tag, "stylesheets");
    document instanceof XMLDocument && manifest_settings.reverse().map(stylesheet => {
        return_value.addStylesheet(stylesheet);
    });
    //window.top.dispatchEvent(new xover.listener.Event(`response`, { request }, response)); 
    if (response.ok) {
        handlers.forEach(handler => handler(return_value, response, request));
        window.top.dispatchEvent(new xover.listener.Event(`success`, { url, request }, response));
    } else {
        window.top.dispatchEvent(new xover.listener.Event(`failure`, { url, request }, response));
    }

    if (!response.ok && (typeof (settings.rejectCodes) == 'number' && response.status >= settings.rejectCodes || settings.rejectCodes instanceof Array && settings.rejectCodes.includes(response.status))) {
        return Promise.reject(response);
    } else if (response.status == 401 && url.host == location.host) {
        xover.session.status = "unauthorized";
    }
    if (response.status == 204) {
        document = xover.xml.createDocument();
    }

    if (response.ok) {
        if (
            (request.headers.get("Accept") || "").indexOf("*/*") != -1 ||
            request.headers.get("Accept").split(/\s*,\s*/g).includes(response.headers.get("content-type")) ||
            xover.mimeTypes[response.bodyType] == request.headers.get("Accept") ||
            (request.headers.get("Accept") || "").replace("text/plain", "text").indexOf(document.type) != -1 ||
            (request.headers.get("Accept") || "").replace("text/plain", "text").indexOf(response.bodyType) != -1) {
            return Promise.resolve(response);
        } else {
            return Promise.reject(response);
        }
    } else {
        return Promise.reject(response);
    }


    //if (response.status == 204) {
    //    return Promise.reject(response);
    //} else if ([409, 449, 503].includes(response.status)) {
    //    return Promise.reject(response);
    //} else if (
    //    (request.headers.get("Accept") || "").indexOf("*/*") != -1 ||
    //    xover.mimeTypes[response.bodyType] == request.headers.get("Accept") ||
    //    (request.headers.get("Accept") || "").replace("text/plain", "text").indexOf(document.type) != -1 ||
    //    (request.headers.get("Accept") || "").replace("text/plain", "text").indexOf(response.bodyType) != -1) {
    //    return Promise.resolve(response);
    //} else if (response.bodyType == 'html' && document instanceof DocumentFragment) {
    //    xover.dom.createDialog(document);
    //}
    //return Promise.reject(response);
}

xover.fetch.from = async function () {
    let response = await xover.fetch.apply(this, arguments);
    return response.body;
}

xover.fetch.xml = async function (url, ...args) {
    if (!url) return null;
    if (!(url instanceof URL)) {
        url = new xover.URL(url);
        url.settings["headers"].set("Accept", url.settings["headers"].get("Accept") || "text/xml, text/xsl")
    }

    try {
        let response = await xover.fetch.apply(this, [url, ...args]);
        let return_value = response.document || response;
        //if (!return_value.documentElement && response.headers.get('Content-Type').toLowerCase().indexOf("json") != -1) {
        //    return_value = xover.xml.fromJSON(return_value.documentElement);
        //}
        if (xover.session.debug) {
            for (let el of return_value.select(`//xsl:template[not(contains(@mode,'-attribute') or contains(@mode,':attribute'))]/*[not(self::xsl:param or self::xsl:text or self::xsl:value-of or self::xsl:choose or self::xsl:if or self::xsl:attribute or self::xsl:variable or ancestor::xsl:element or self::xsl:copy or following-sibling::xsl:apply-templates[contains(@mode,'-attribute') or contains(@mode,':attribute')])]|//xsl:template//xsl:*//html:option|//xsl:template//html:*[not(parent::html:*)]|//xsl:template//svg:*[not(ancestor::svg:*)]|//xsl:template//xsl:comment[.="debug:info"]`).filter(el => !el.selectFirst(`preceding-sibling::xsl:text|preceding-sibling::text()[normalize-space()!='']`))) {
                let ancestor = el.select("ancestor::xsl:template[1]|ancestor::xsl:if[1]|ancestor::xsl:when[1]|ancestor::xsl:for-each[1]|ancestor::xsl:otherwise[1]").pop();
                let debug_node = xover.xml.createNode((el.selectSingleNode('preceding-sibling::xsl:attribute') || el.selectSingleNode('self::html:textarea')) && `<xsl:attribute xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:debug="http://panax.io/debug" name="debug:template">${new xover.URL(url).href}: template ${el.$$(`ancestor::xsl:template[1]/@*`).map(attr => `${attr.name}="${attr.value}"`).join(" ")} </xsl:attribute>` || `<xsl:comment xmlns:xsl="http://www.w3.org/1999/XSL/Transform">&lt;template 
scope="<xsl:value-of select="name(ancestor-or-self::*[1])"/><xsl:if test="not(self::*)"><xsl:value-of select="concat('/@',name())"/></xsl:if>"
file="${new xover.URL(url).href}"
>${ancestor.localName == 'template' ? '' : `
&lt;!- -${ancestor.nodeName} ${[...ancestor.attributes].filter(attr => !['xo:id'].includes(attr.nodeName)).map(attr => `${attr.nodeName}="${attr.value.replace(/>/g, '&gt;').replace(/</g, '&lt;').replace(/--/g, '- -')}"`)}- -&gt;`}
${el.$$(`ancestor::xsl:template[1]/@*`).map(attr => `${attr.name}="${new Text(attr.value).toString()}"`).join(" ")} &lt;/template></xsl:comment>`);
                if (el.selectSingleNode('self::xsl:comment[.="debug:info"]')) {
                    el.replaceWith(debug_node)
                } else if (el.selectSingleNode('self::html:textarea')) {
                    el.insertFirst(debug_node)
                } else {
                    el.appendBefore(debug_node)
                }
            }
        }
        if (return_value.documentElement && return_value.selectFirst('xsl:*')) {
            //if (!return_value.documentElement.resolveNS('')) {
            //    return_value.documentElement.setAttributeNS(xover.spaces["xmlns"], "xmlns", xover.spaces["xhtml"])
            //}/*desn't work properly as when declared from origin */
            if (!return_value.documentElement.resolveNS('xo')) {
                return_value.documentElement.setAttributeNS(xover.spaces["xmlns"], "xmlns:xo", xover.spaces["xo"])
            }

            for (let el of return_value.select(`(//xsl:template[not(@match="/")]//html:*[not(self::html:script)]|//svg:*[not(ancestor::svg:*)])[not(ancestor-or-self::*[@xo-attribute or @xo-scope])]`)) {
                el.set("xo-attribute", "{name(current()[not(self::*)])}")
            }

            for (let el of return_value.select(`(//xsl:template[not(@match="/")]//html:*[not(self::html:script)]|//svg:*[not(ancestor::svg:*)])[not(ancestor-or-self::*[@xo-scope])]`)) {
                el.set("xo-scope", "{current()[not(self::*)]/../@xo:id|@xo:id}");
            }

            for (let el of return_value.$$(`//xsl:template[not(@match="/")]//xsl:element`)) {
                el.insertFirst(xover.xml.createNode(`<xsl:attribute name="xo-attribute"><xsl:value-of select="name(current()[not(self::*)])"/></xsl:attribute>`));
                el.insertFirst(xover.xml.createNode(`<xsl:attribute name="xo-scope"><xsl:value-of select="current()[not(self::*)]/../@xo:id|@xo:id"/></xsl:attribute>`));
            }
        }
        return_value.documentElement && return_value.documentElement.selectNodes("xsl:import|xsl:include|//processing-instruction()").map(async node => {
            let href = node.href || node.getAttribute("href");
            if (!href.match(/^\//)) {
                let new_href = new URL(href, response.url || response.href).href;//Permite que descargue correctamente los templates, pues con documentos vacíos creados, no se tiene referencia de la URL actual (devuelve about:blank). Con esto se corrige
                if (node instanceof ProcessingInstruction) {
                    node.href = new_href;
                } else {
                    node.setAttributeNS(null, "href", new_href);
                }
            }
        });
        let imports = return_value.documentElement && return_value.documentElement.selectNodes("xsl:import|xsl:include|//processing-instruction()").reduce((arr, item) => { arr.push(item.href || item.getAttribute("href")); return arr; }, []) || [];
        if (imports.length) {
            function assert(condition, message) {
                if (!condition) {
                    throw new Error(message);
                }
            }

            try {
                let rejections = []
                await Promise.all(imports.map(href => xover.sources[href].fetch().catch(e => rejections.push(e))));
                if (xover.session.debug) {
                    return_value.select(`//xsl:*[xsl:param]`).forEach(template => {
                        let param_names = [...template.select(`xsl:param/@name`).map(param => param.value)];
                        try {
                            assert(param_names.length == [...new Set(param_names)].length, `Los nombres de los parámetros deben ser únicos en: ${template.nodeName} ${template.select(`@*`).map(attr => `${attr.name}="${new Text(attr.value).toString()}"`).join(" ")}>`)
                        } catch (e) {
                            rejections.push(e)
                        }
                    })
                }
                if (rejections.length) {
                    return Promise.reject(xover.xml.createNode(`<fieldset xmlns="http://www.w3.org/1999/xhtml"><legend>En el archivo ${url.href || url}, se encuentran los siguientes problemas: </legend><ol>${rejections.map(item => `<li>${item.href || item.url || item}${item.status == 404 ? ' - No encontrado' : ''}</li>`)}</ol></fieldset>`));
                }
                return_value = return_value.consolidate();
            } catch (e) {
                return Promise.reject(e);
            }
        }

        return return_value;
    } catch (e) {
        return Promise.reject(e);
    }
}

xover.fetch.json = async function (url, settings = { rejectCodes: 400 }, on_success) {
    settings["headers"] = (settings["headers"] || {});
    settings["headers"]["Accept"] = (settings["headers"]["Accept"] || "application/json")
    let return_value = await xover.fetch.call(this, url, settings, on_success).then(response => response.json);
    return return_value;
}

xover.xml.fromString = function (xmlString) {
    if (window.DOMParser) {
        parser = new DOMParser();
        xmlDoc = parser.parseFromString(xmlString, "text/xml");
    }
    else // Internet Explorer
    {
        xmlDoc = xover.xml.createDocument();
        xmlDoc.loadXML(xmlString);
        xmlDoc.setProperty("SelectionLanguage", "XPath");
    }
    return xmlDoc
}

xover.xml.normalizeNamespaces = function (xml) {
    if (!xml || xml instanceof HTMLDocument || xml instanceof HTMLElement) return xml;
    //original_setAttributeNS.call(xml.documentElement, xover.spaces["xmlns"], "xmlns:xsi", xover.spaces["xsi"]);
    //return xml;
    var xsl_transform = xover.sources["xover/normalize_namespaces.xslt"];
    if (navigator.userAgent.indexOf("Firefox") != -1) {
        xsl_transform.selectNodes("//xsl:copy-of[contains(@select,'namespace::')]").remove();
    }
    return xml.transform(xsl_transform);
}

xover.xml.isValid = function (input) {
    return (input instanceof XMLDocument);
}

xover.xml.tryParse = function (input) {
    try {
        let output = xover.xml.createDocument(input, { silent: true });
        return (output.getElementsByTagName('parsererror') || []).length && input || output;
    } catch (e) {
        return false;
    }
}

xover.xml.createFragment = function (xml_string) {
    let frag = window.document.createDocumentFragment();
    let p = window.document.createElement('p');
    p.innerHTML = xml_string;
    frag.append(...p.childNodes);
    return frag
}

xover.xml.createNode = function (xml_string, notify_error) {
    let doc = xover.xml.createDocument(xml_string, notify_error)
    return doc.documentElement;
}

xover.xml.createElement = function (tagName) {
    let { prefix } = xover.xml.getAttributeParts(tagName);
    let namespace = xover.stores.active.documentElement.resolveNS(prefix)
    return document.implementation.createDocument(namespace || "", tagName, null).documentElement;
}

xover.xml.clone = function (source) {
    return xover.xml.createDocument(source);
}

xover.xml.fromHTML = function (document) {
    let xhtml = document.implementation.createDocument("http://www.w3.org/1999/xhtml", "", null);
    if (element) {
        xhtml.appendChild(xhtml.importNode(document.documentElement || element, true));
    }
    return xhtml
}

xover.data.createMessage = function (message_content, message_type) {
    var message = xover.xml.createDocument('<xo:message xmlns:xo="http://panax.io/xover" type="' + (message_type || "exception") + '"/>').reseed();
    if (message_content instanceof HTMLElement) {
        message.documentElement.set(message_content)
    } else {
        message.documentElement.set(message_content.toString());
    }
    console.trace();
    return message;
}

xover.sources.defaults["styles.css"] = xover.xml.createDocument(`
<style>
iframe {
    display: block;       
    background: #000;
    border: none;         
    height: 100vh;        
    width: 100vw;
    resize: both;
}

dialog {
  max-width: 50ch;
}
dialog > * {
  margin: 0 0 0.5rem 0;
}

dialog::-webkit-backdrop {
  background: rgba(0, 0, 0, 0.4);
}

dialog::backdrop {
  background: rgba(0, 0, 0, 0.4);
}

form {
  display: grid;
  gap: 1em;
}

footer {
    position: fixed !important;
    bottom: 0px;
    display: block;
    margin-bottom: 15px;
}

header {
    position: fixed !important;
    top: 0px;
    display: block;
    margin-top: 15px;
}
</style>`);

xover.sources.defaults["error.xslt"] = xover.xml.createDocument(`
<xsl:stylesheet version="1.0"                                                                           
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"                                                    
    xmlns="http://www.w3.org/1999/xhtml">                                                               
    <xsl:output method="xml" indent="no" />                                                             
    <xsl:template match="node()">                                                                       
    <div class="jumbotron">                                                                             
        <div class= "container text-center" style="padding-top:30pt; padding-bottom:30pt;">             
            <h2 class="text-center">Parece que la versión que usas ha cambiado o contiene errores en este módulo. Por favor actualiza tus librerías o repórtalo con el administrador.</h2>    
            <br/><button type="button" class="btn btn-primary btn-lg text-center" onclick="xover.stores.active.sources.reload()">Actualizar librerías</button>                               
            <br/><br/><button type="button" class="btn btn-primary btn-lg text-center" onclick="xover.session.save()">Reportar</button>                                    
        </div>                                                                                          
    </div>                                                                                              
    </xsl:template>                                                                                     
    <xsl:template match="text()|processing-instruction()|comment()"/>                                   
</xsl:stylesheet>`);

xover.sources.defaults["empty.xslt"] = xover.xml.createDocument(`
<xsl:stylesheet version="1.0"                                                                           
    xmlns:xo="http://panax.io/xover"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"                                                    
    xmlns:js="http://panax.io/xover/javascript"                                                    
    xmlns="http://www.w3.org/1999/xhtml">                                                               
    <xsl:output method="xml" indent="no" />
    <xsl:param name="js:snapshots"><![CDATA[self.store && self.store.snapshots.length || 0]]></xsl:param>
    <xsl:template match="xo:empty">                                                                       
    <div class="jumbotron">                                                                             
        <div class= "container text-center" style="padding-top:30pt; padding-bottom:30pt;">             
            <h2 class="text-center">El documento está vacío.</h2>    
            <xsl:if test="$js:snapshots&gt;0">
            <br/><button type="button" class="btn btn-primary btn-lg text-center" onclick="this.store.undo()">Deshacer último cambio</button>
            <br/><br/><button type="button" class="btn btn-primary btn-lg text-center" onclick="this.store.document.fetch()">Descargar desde la fuente</button>
            </xsl:if>
        </div>                                                                                          
    </div>                                                                                              
    </xsl:template>                                                                                     
    <xsl:template match="text()|comment()|processing-instruction()"/>                                   
</xsl:stylesheet>`);

xover.sources.defaults["shell.xslt"] = xover.xml.createDocument(`
<xsl:stylesheet version="1.0"                                                                           
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"                                                    
    xmlns="http://www.w3.org/1999/xhtml">                                                               
    <xsl:output method="xml" indent="no" />                                                             
    <xsl:template match="node()">                                                                       
    <main><div class="p-5 mb-4 bg-light rounded-3">
      <div class="container-fluid py-5">
        <h1 class="display-5 fw-bold">Welcome to xover!</h1>
        <p class="col-md-8 fs-4">Please create your templates in your own transformation file.</p><p>Starting with shell.xslt is a good idea.</p>
        <a href="https://xover.dev" target="_blank">Show me how!</a>
      </div>
    </div>
    </main>
    </xsl:template>                                                                                     
    <xsl:template match="text()|processing-instruction()|comment()"/>                                   
</xsl:stylesheet> `);

xover.sources.defaults["login.xslt"] = xover.xml.createDocument(`
<xsl:stylesheet version="1.0"                                                                           
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"                                                    
    xmlns="http://www.w3.org/1999/xhtml">                                                               
    <xsl:output method="xml" indent="no" />                                                             
    <xsl:template match="node()">                                                                       
    <div class="p-5 mb-4 bg-light rounded-3">
      <div class="container-fluid py-5">
        <h1 class="display-5 fw-bold">Welcome to xover!</h1>
        <p class="col-md-8 fs-4">It looks like login feature is enabled and requires a template.</p><p>Please create your templates in your own transformation file.</p><p>Starting with login.xslt is a good idea.</p>
        <a href="https://xover.dev" target="_blank">Show me how!</a>
      </div>
    </div>
    </xsl:template>                                                                                     
    <xsl:template match="text()|processing-instruction()|comment()"/>                                   
</xsl:stylesheet> `);

xover.sources.defaults["loading.xslt"] = xover.xml.createDocument(`
<xsl:stylesheet version="1.0"                                                                           
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:js="http://panax.io/xover/javascript"
    xmlns="http://www.w3.org/1999/xhtml" exclude-result-prefixes="js">
    <xsl:output method="xml" indent="no" />
    <xsl:param name="js:icon"><![CDATA[[...document.querySelectorAll('link[type = "image/x-icon"]')].map(el => el && el.getAttribute("href"))[0]]]></xsl:param>
    <xsl:template match="node()">                                                                       
    <div class="loading" onclick="this.remove()" role="alert" aria-busy="true">
      <div class="modal_content-loading">
        <div class="modal-dialog modal-dialog-centered">
          <div class="no-freeze-spinner">
            <div id="no-freeze-spinner">
              <div>
                <i class="icon" style="justify-content: center; display: flex; align-items: center;">
                    <img src="{$js:icon}" class="ring_image" onerror="this.remove()"/><span class="details" style="position: absolute; top: 3rem; width: 100%;"><progress style="display:none; width: 100%; accent-color: var(--progress-color, green);" max="100" value="0" aria-label="Loading…">0%</progress></span>
                </i>
                <div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    </xsl:template>                                                                                     
    <xsl:template match="text()|processing-instruction()|comment()"/>                                   
</xsl:stylesheet>`);

xover.sources.defaults["message.xslt"] = xover.xml.createDocument(`
<xsl:stylesheet version="1.0" 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:xo="http://panax.io/xover"
  xmlns:html="http://www.w3.org/1999/xhtml"
  xmlns="http://www.w3.org/1999/xhtml"
  exclude-result-prefixes="xsl xo"
>
  <xsl:output method="xml"
     omit-xml-declaration="yes"
     indent="yes" standalone="no"/>

  <xsl:template match="xo:message">
    <dialog open="open" style="width: 450px; height: 200px; margin: 0 auto; top: 25vh; padding: 1rem; overflow: auto;" role="alertdialog"><header style="display:flex;justify-content: end;"><button type="button" formmethod="dialog" aria-label="Close" onclick="this.closest('dialog').remove();" style="background-color:transparent;border: none;"><svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" fill="currentColor" class="bi bi-x-circle text-primary_messages" viewBox="0 0 24 24"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"></path><path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"></path></svg></button></header><form method="dialog" onsubmit="closest('dialog').remove()"><h4 style="margin-left: 3rem !important;"><xsl:apply-templates/></h4></form></dialog>
  </xsl:template>

  <xsl:template match="html:*"><xsl:copy-of select="."/></xsl:template>
</xsl:stylesheet>`);

xover.data.default = xover.xml.createDocument('<?xml-stylesheet type="text/xsl" href="shell.xslt" role="shell" target="body"?><shell:shell xmlns:xo="http://panax.io/xover" xmlns:shell="http://panax.io/shell" xmlns:state="http://panax.io/state" xmlns:source="http://panax.io/source" xo:id="shell" xo:hash=""></shell:shell>');

xover.xml.Empty = function () {
    if (!(this instanceof xover.xml.Empty)) return new xover.xml.Empty();
    return xover.xml.createDocument();
}

xover.xml.safeEntities = {
    "<": "&lt;"
}

xover.xml.encodeEntities = function (text) {
    new_text = text;
    new_text = new_text.replace(/</g, xover.xml.safeEntities["<"]);
    return new_text;
}

xover.dom.findClosestElementWithAttribute = function (element, attribute) {
    if (!element) return element;
    if (element.getAttribute(attribute)) {
        return element;
    } else if (element.parentElement) {
        return xover.dom.findClosestElementWithAttribute(element.parentElement, attribute);
    } else {
        return undefined;
    }
}

xover.dom.findClosestElementWithTagName = function (element, tagName) {
    if (!element) return element;
    if ((element.tagName || "").toUpperCase() == tagName.toUpperCase()) {
        return element;
    } else if (element.parentElement) {
        return xover.dom.findClosestElementWithTagName(element.parentElement, tagName);
    } else {
        return undefined;
    }
}

xover.dom.findClosestElementWithClassName = function (element, className) {
    if (!element) return element;
    var regex = new RegExp('\b(' + className + ')\b', "ig");

    if (element.classList && element.classList.contains && element.classList.contains(className)) {
        return element;
    } else if (element.parentElement) {
        return xover.dom.findClosestElementWithClassName(element.parentElement, className);
    } else {
        return undefined;
    }
}

xover.dom.findClosestElementWithId = function (element) {
    if (!element) return element;
    if (element.id && !element.id.startsWith("_")) {
        return element;
    } else if (element.parentElement) {
        return xover.dom.findClosestElementWithId(element.parentElement);
    } else {
        return undefined;
    }
}

xover.dom.setEncryption = function (dom, encryption) {
    var encryption = (encryption || "UTF-7")
    if (typeof (dom.selectSingleNode) != 'undefined') {
        var meta_encoding = dom.selectSingleNode('//*[local-name()="meta" and @http-equiv="Content-Type" and not(contains(@content,"' + encryption + '"))]');
        if (meta_encoding) {
            meta_encoding.setAttributeNS(null, "content", "text/html; charset=" + encryption);
        }
    } else {
        var metas = dom.querySelectorAll('meta[http-equiv="Content-Type"]');
        if (metas.length && metas[0].content.indexOf(encryption) != -1) {
            metas[0].content.content = "text/html; charset=" + encryption
        }
    }
}

xover.dom.refresh = async function () {
    var { forced } = (arguments[0] || {});
    if (forced) {
        xover.stores.active.sources.clear(true);
    }
    return xover.stores.active.render(forced);
}

Object.defineProperty(xover.dom.refresh, 'interval', {
    value: function (seconds) {
        var self = this;
        //xover.session.live.running = live;
        var refresh_rate;
        var _seconds = seconds;
        this.seconds = _seconds;
        if (this.Interval) window.clearInterval(this.Interval);
        if (seconds == 0) {
            window.console.info('Auto refresh stopped.');
        } else {
            window.console.info(`Starts refresh of ${xover.stores.active.tag} for every ${seconds} seconds.`);
        }
        if (!seconds) return;

        refresh_rate = (refresh_rate || 5);
        refresh_rate = (refresh_rate * 1000);
        var refresh = async function () {
            if (!this.seconds) {
                if (this.Interval) window.clearInterval(this.Interval);
                window.console.info('Auto refresh stopped.');
                return;
            }
            window.console.info('Checking for changes in session...');
            await xover.dom.refresh({ forced: true });
        };

        self.Interval = setInterval(function () {
            refresh.apply(self)
        }, refresh_rate);
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.dom.refresh, 'stop', {
    value: function () {
        xover.dom.refresh.seconds = undefined;
        if (xover.dom.refresh.Interval) {
            window.clearInterval(xover.dom.refresh.Interval);
            xover.dom.refresh.Interval = undefined;
        }
        window.console.info('Auto refresh stopped.');
    },
    writable: false, enumerable: false, configurable: false
});

xover.dom.clear = function (target) {
    if (target === undefined) {
        target = document.querySelector('body');
    } else if (typeof (target) == "string") {
        target = document.querySelector(target);
    }
    if (!(target && target.innerHTML)) return;
    target.innerHTML = '';
}

xover.data.getFirstRecord = function (xml) {
    var oXML = xover.xml.createDocument(xover.stores.active);
    try {
        return oXML.selectSingleNode('/*/*[1]');
    } catch (e) {
        for (let nodeItem = oXML.childNodes.length; nodeItem > 0; --nodeItem) {
            var nodeElement = oXML.childNodes[nodeItem - 1];
            if (nodeElement.nodeType == 1) {
                return nodeElement.firstElementChild; //Equivalente a /*/*[1]
            }
        }
    }
}

xover.Store = function (xml, ...args) {
    if (!(this instanceof xover.Store)) return new xover.Store(xml, args[0]);
    let self = this;
    let store = this;
    let _this_arguments = args;
    if (!(xml instanceof Document)) return Promise.reject(`A Store should be created with a document`);
    let __document = xml; //Before: xover.xml.createDocument(xml); //Now should remain reference for current 
    if (__document.source instanceof xover.Source && !__document.source.hasOwnProperty("save")) {
        Object.defineProperty(__document.source, 'save', {
            value: async function () {
                xover.storehouse.write('sources', __document.source.tag, __document.toString());
            },
            writable: false, enumerable: false, configurable: false
        })
    }
    let _undo = [];
    let _redo = [];
    let config = args[0] && args[0].constructor === {}.constructor && args[0];
    let _tag;
    let _hash = config && config['hash'] || undefined;
    let _initiator = config && config["initiator"] || undefined;
    let _store_stylesheets = [];
    let _sources = new Proxy({}, {
        get: function (self, key) {
            if (key in self) {
                return self[key];
            }
            if (!self.hasOwnProperty(key)) {
                self[key] = self[key] || xover.sources[key].cloneNode(true);
            }
            if (self[key] instanceof Document) {
                self[key].store = store;
            }
            return self[key];
        },
        set: function (self, key, value) {
            return self[key] = value //|| target[name]; //Ahora se permite que se asigne undefined para que funcione el método clear.
        }
    });

    let _async_save;
    if (!this.hasOwnProperty('save')) {
        Object.defineProperty(this, 'save', {
            value: async function () {
                let source = __document.source;
                if (source) {
                    xover.session.setKey(store.tag, { source: source.tag });
                    source.save();
                } else {
                    _async_save = _async_save || xover.delay(1).then(async () => {
                        xover.storehouse.write('sources', store.tag, __document);
                        _async_save = undefined;
                    });
                }
            },
            writable: false, enumerable: false, configurable: false
        })
    }

    if (!this.hasOwnProperty('source')) {
        Object.defineProperty(this, 'source', {
            get: function () {
                return __document.source
            }
        });
    }

    if (!this.hasOwnProperty('remove')) {
        Object.defineProperty(this, 'remove', {
            value: function () {
                delete xover.stores[_tag];
            }
        });
    }

    Object.defineProperty(_sources, 'clear', {
        value: function (forced) {
            Object.keys(this).map((key) => {
                let item = _sources[key]
                if (item.source && item.documentElement) {
                    item.documentElement.remove();
                    if (forced) {
                        let from_sources = xover.sources[key];
                        from_sources.documentElement && from_sources.documentElement.remove();
                    }
                }
            });
            return _sources;
        },
        writable: false, enumerable: false, configurable: false
    })

    Object.defineProperty(_sources, 'load', {
        value: async function (list) {
            //store.state.loading = true;
            let stylesheets = await Promise.all(store.stylesheets.getDocuments().map(document => document.documentElement && document || document.fetch().then(document => document))).then(document => document);
            return stylesheets;
        },
        writable: false, enumerable: false, configurable: false
    })

    Object.defineProperty(_sources, 'reload', {
        value: async function (list) {
            _sources.clear(true);
            store.render();
            return _sources;
        },
        writable: false, enumerable: false, configurable: false
    })

    Object.defineProperty(_sources.reload, 'interval', {
        value: function (seconds) {
            var self = this;
            //xover.session.live.running = live;
            var refresh_rate;
            this.paused = false;
            var _seconds = (seconds || 3);
            this.seconds = _seconds;
            if (self.Interval) {
                window.clearInterval(self.Interval);
                self.Interval = undefined;
            }
            if (seconds == 0) {
                window.console.info('Auto refresh stopped.');
                return;
            } else {
                window.console.info(`Start refresh of ${xover.stores.active.tag} for every ${this.seconds} seconds.`);
            }

            refresh_rate = this.seconds;
            refresh_rate = (refresh_rate * 1000);
            var refresh = async function () {
                if (!this.seconds) {
                    if (this.Interval) window.clearInterval(this.Interval);
                    window.console.info('Auto refresh stopped.');
                    return;
                }
                if (!this.paused) {
                    window.console.info('Checking for changes in session...');
                    this();
                    store.render();
                }
            };

            self.Interval = setInterval(function () {
                if (!self.interval.hasOwnProperty('stop')) {
                    Object.defineProperty(self.interval, 'stop', {
                        value: function () {
                            self.seconds = undefined;
                            if (self.Interval) {
                                window.clearInterval(self.Interval);
                                self.Interval = undefined;
                            }
                            delete self.interval["stop"];
                            delete self.interval["pause"];
                            delete self.interval["continue"];
                            window.console.info('Auto refresh stopped.');
                        },
                        writable: false, enumerable: false, configurable: true
                    });
                }
                if (!self.interval.hasOwnProperty('pause')) {
                    Object.defineProperty(self.interval, 'pause', {
                        value: function () {
                            self.paused = true;
                            if (!self.interval.hasOwnProperty('continue')) {
                                Object.defineProperty(self.interval, 'continue', {
                                    value: function () {
                                        self.paused = false;
                                        delete self.interval["continue"];
                                    },
                                    writable: false, enumerable: false, configurable: true
                                });
                            }
                            window.console.info('Auto refresh paused.');
                        },
                        writable: false, enumerable: false, configurable: true
                    });
                }
                refresh.apply(self)
            }, refresh_rate);
        },
        writable: false, enumerable: false, configurable: false
    });

    //for (let endpoint in xover.manifest.server) {
    //    Object.defineProperty(store, endpoint, {
    //        value: async function (...arguments) {
    //            let args = arguments;
    //            if (args.length === 1) {
    //                if (args[0].apply) {
    //                    args = args[0].apply(store, args);
    //                }
    //                if (!args) { console.error(`Method ${endpoint} should be executed with arguments.`) }
    //            }
    //            return xover.server[endpoint].apply(store, args);
    //        },
    //        writable: true, enumerable: false, configurable: true
    //    });
    //}

    var _isActive = undefined;

    this.state = new Proxy({}, {
        get: function (target, name) {
            if (!__document.documentElement) return target[name];
            try {
                return JSON.parse(__document.documentElement.getAttribute(`state:${name}`)) //name in target && target[name];
            } catch (e) {
                return (__document.documentElement.getAttribute(`state:${name}`));
            }
        },
        set: function (target, name, value) {
            if (value && ['function'].includes(typeof (value))) {
                throw (new Error('State value is not valid type'));
            }
            let old_value = store.state[name]
            if (old_value == value) return;
            target[name] = value;
            if (!__document.documentElement) return;
            __document.documentElement.setAttributeNS(xover.spaces["state"], `state:${name}`, value);
        }
    })

    __document.status = "loading"

    Object.defineProperty(this, 'sources', {
        get: function () {
            _sources.merge(this.stylesheets.reduce((obj, curr) => { obj[curr.href] = _sources[curr.href]; return obj }, {}));
            return _sources;
        }
    })

    Object.defineProperty(this, 'tag', {
        get: function () {
            return '#' + _tag.split(/^#/).pop();
        },
        set: function (input) {
            return _tag = input;
        }
    })

    Object.defineProperty(this, 'hash', {
        get: function () {
            return [_hash, xover.manifest.getSettings(this, 'hash').pop(), store.tag].coalesce();
            /*return '#' + Array.prototype.coalesce(_hash, __document.documentElement && Array.prototype.coalesce(__document.documentElement.getAttributeNS("http://panax.io/xover", "hash"), __document.documentElement.getAttributeNS("http://panax.io/xover", "tag"), __document.documentElement.localName.toLowerCase()), _tag).split(/^#/).pop();*/
        },
        set: function (input) {
            //if (__document.documentElement) {
            //    __document.documentElement.setAttributeNS(xover.spaces["x"], "xo:hash", input);
            //}
            _hash = input;
            xover.site.hash = _hash;
        }
    });

    Object.defineProperty(this, 'snapshots', {
        get: function () {
            return _undo;
        }
    });

    Object.defineProperty(this, 'findById', {
        value: function (xid) {
            return __document.selectSingleNode('//*[@xo:id="' + xid + '"]')
        }
    });

    Object.defineProperty(this, 'takeSnapshot', {
        value: function () {
            _undo.push(__document.cloneNode(true));
            _redo = [];
        },
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'undo', {
        value: function () {
            let snapshot = _undo.pop();
            if (snapshot) {
                _redo.unshift(__document.cloneNode(true));
                __document = snapshot;
                //__document.store = this;
                //xover.dom.refresh({ trigger_bindings: false })
                this.render(/*true*/);
            }
        },
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'redo', {
        value: function () {
            let snapshot = _redo.shift();
            if (snapshot) {
                _undo.push(__document.cloneNode(true));
                __document = snapshot;
                //__document.store = this;
                //xover.dom.refresh({ trigger_bindings: false })
                this.render(/*true*/);
            }
        },
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'initiator', {
        get: function () {
            return _initiator;
        },
        set: function (input) {
            _initiator = input;
        }
    });

    Object.defineProperty(this, 'document', {
        get: function () {
            if (!__document) {
                __document = (__document || xover.xml.createDocument(""));
            }
            __document.store = this;
            return __document;
        },
        set: function (input) {
            //input.href = input.href || __document.href;
            //input.url = input.url || __document.url;
            //__document = input;
            //if (typeof (input) == 'string') {
            //    __document = xover.xml.createDocument(input)
            //}
            //if (__document.documentElement) {
            //    __document.documentElement.setAttributeNS(xover.spaces["x"], "xo:tag", (this.tag.replace(/^#/, '') || ""));
            //    //__document.documentElement.setAttributeNS(xover.spaces["state"], "state:refresh", "true");
            //}
            //xover.stores[this.tag] = self;
            if (!(input instanceof Document)) {
                return Promise.reject(`Invalid input document for store`)
            }
            input.reseed();
            if (input instanceof Document) {
                __document.replaceBy(input)
            } else {
                __document = input;
            }
            const config = { characterData: true, attributes: true, childList: true, subtree: true };
            let store = self;
            const distinctMutations = function (mutations) {
                return mutations.filter((mutation, index, self) => {
                    const matchingMutation = self.find((otherMutation) => {
                        return (
                            otherMutation.type === mutation.type &&
                            otherMutation.target === mutation.target &&
                            otherMutation.attributeName === mutation.attributeName &&
                            otherMutation.attributeNamespace === mutation.attributeNamespace
                        );
                    });
                    return matchingMutation === mutation;
                });
            }

            const callback = (mutationList) => {
                mutationList = mutationList.filter(mutation => !mutation.target.disconnected && (mutation.attributeName == 'value' || !["http://panax.io/xover", "http://www.w3.org/2000/xmlns/"].includes(mutation.attributeNamespace)))//.filter(mutation => !(mutation.target instanceof Document));
                //mutationList = distinctMutations(mutationList); //removed to allow multiple removed nodes
                if (!mutationList.length) return;
                mutated_targets = new Map();
                for (let mutation of mutationList) {
                    let inserted_ids = [];
                    let value = mutated_targets.get(mutation.target) || {};
                    value.addedNodes = value.addedNodes || [];
                    value.addedNodes.push(...mutation.addedNodes);
                    value.removedNodes = value.removedNodes || [];
                    value.removedNodes.push(...mutation.removedNodes);
                    value.attributes = value.attributes || {};
                    if (mutation.type == "attributes") {
                        value.attributes[mutation.attributeNamespace || ''] = value.attributes[mutation.attributeNamespace] || {};
                        value.attributes[mutation.attributeNamespace || ''][mutation.attributeName] = {};
                    }
                    mutated_targets.set(mutation.target, value);
                    [...mutation.addedNodes].forEach((addedNode) => {
                        inserted_ids = inserted_ids.concat(addedNode.select(`.//@xo:id`).map(node => node.value));
                    })
                    //let duplicated_node = inserted_ids.find(id => mutation.target.selectFirst(`(//*[@xo:id="${id}"])[2]`));
                    //if (duplicated_node) {
                    //    Promise.reject(`Duplicated id ${duplicated_node}`)
                    //    //console.log(inserted_ids)
                    //}
                }
                if (event && event.type == 'input') {
                    event.srcElement.preventChangeEvent = true;
                }
                if (event && event.type == 'change' && event.srcElement.preventChangeEvent) {
                    event.srcElement.preventChangeEvent = undefined;
                }
                //if (event) {
                //    console.log(`${event.type}`)
                //}
                let sections_to_render = new Map();
                for (let section of xover.site.sections.filter(section => section.store === self)) {
                    if (event && event.type == 'input' && section.contains(event.srcElement) && event.srcElement.section == section) {
                        continue
                    }
                    sections_to_render.set(section); continue; /* let's skip all checkings and render every change*/

                    if (!section.stylesheet.documentElement || mutationList.find(mutation => mutation.type === 'childList')) {
                        section.render()
                    }
                    //if (!sections_to_render.get(section)) {
                    //    if (mutationList.find(mutation => mutation.target instanceof Document)) {
                    //        sections_to_render.set(section);
                    //    }
                    //}
                    let listeners = [...section.querySelectorAll('xo-listener')].filter(el => el.store === self && el.closest('[xo-stylesheet]') === section);
                    for (listener of listeners) {
                        for (let mutation of mutationList) {
                            if (!sections_to_render.get(section)) {
                                if (listener.getAttribute("node")) {
                                    if (mutation.target instanceof Element && mutation.target.matches(listener.getAttribute("node")) || [...mutation.removedNodes, ...mutation.addedNodes].find(el => el.matches(listener.getAttribute("node")))) {
                                        sections_to_render.set(section);
                                    }
                                }
                                if (mutation.type === 'attributes') {
                                    let attrib = listener.getAttributeNode("attribute");
                                    if (attrib) {
                                        let attr = mutation.target.getAttributeNodeNS(mutation.attributeNamespace, mutation.attributeName);
                                        if (!attr) {
                                            attr = mutation.target.createAttributeNS(mutation.attributeNamespace, mutation.attributeName, null);
                                        }
                                        let attrib_node = mutation.target.getAttributeNode(attrib.value);
                                        if (attrib && !attrib_node) {
                                            try {
                                                attrib_node = mutation.target.createAttribute(attrib.value, null)
                                            } catch (e) {
                                                let { prefix, name } = xover.xml.getAttributeParts(attrib.value)
                                                if (prefix && name == '*') {
                                                    let ns = attr.resolveNS(prefix) || xo.spaces[prefix];
                                                    if (attr.namespaceURI == ns) {
                                                        sections_to_render.set(section)
                                                    }
                                                }
                                                continue;
                                            }
                                        }
                                        if (attrib_node.isEqualNode(attr)) {
                                            sections_to_render.set(section)
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let attrs = [...section.select('.//@xo-attribute')].filter(el => el.parentNode.store === self && el.parentNode.closest('[xo-stylesheet]') === section);
                    for (attrib of attrs) {
                        for (mutation of mutationList) {
                            if (!sections_to_render.get(section)) {
                                if (event && event.type == 'input' && section.contains(event.srcElement)) {
                                    continue
                                }
                                let scoped_element = attrib.parentNode.closest('[xo-scope]');
                                if (scoped_element && !(mutation.target instanceof Document) && scoped_element.getAttribute("xo-scope") == mutation.target.getAttribute("xo:id")) {
                                    //&& (mutation.type !== 'attributes' || mutation.type === 'attributes' &&
                                    let render = false;
                                    if (attrib.value.indexOf(':') != -1) {
                                        let attr = mutation.target.getAttributeNodeNS(mutation.attributeNamespace, mutation.attributeName);
                                        if (!attr) {
                                            attr = mutation.target.createAttributeNS(mutation.attributeNamespace, mutation.attributeName, null);
                                        }
                                        let attrib_node = mutation.target.getAttributeNode(attrib.value);
                                        if (attrib && !attrib_node) {
                                            try {
                                                attrib_node = mutation.target.createAttribute(attrib.value, null)
                                            } catch (e) {
                                                let { prefix, name } = xover.xml.getAttributeParts(attrib.value)
                                                if (prefix && name == '*') {
                                                    let ns = attr.resolveNS(prefix) || xo.spaces[prefix];
                                                    if (attr.namespaceURI == ns) {
                                                        render = true;
                                                    }
                                                }
                                                continue;
                                            }
                                        }
                                        if (attrib_node.isEqualNode(attr)) {
                                            render = true;
                                        } else {
                                            render = false;
                                        }
                                    } else if (mutation.attributeName == attrib.value) {
                                        render = true
                                    }
                                    if (render) {
                                        sections_to_render.set(section)
                                    }
                                }
                            }
                        }
                    }
                }

                for (let [section] of [...sections_to_render.entries()]) {
                    section.render()
                }
                for (const [target, mutation] of [...mutated_targets]) {
                    /*Known issues: Mutation observer might break if interrupted and page is reloaded. In this case, closing and reopening tab might be a solution. */
                    if (mutation.removedNodes.length) {
                        if (typeof (target.getAttributeNS) === 'function' && !target.getAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "nil") && !(target.firstElementChild || target.textContent)) {
                            target.setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:nil", "true");
                        }
                    }
                    for (let el of [...mutation.addedNodes]) {
                        window.top.dispatchEvent(new xover.listener.Event('append', { target: target }, el));
                        el.selectNodes("descendant-or-self::*[not(@xo:id)]").forEach(el => el.reseed());
                    };
                    if (mutation.addedNodes.length) {
                        window.top.dispatchEvent(new xover.listener.Event('appendTo', { addedNodes: mutation.addedNodes }, target));
                        if (target instanceof Element && target.getAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "nil") && (target.firstElementChild || target.textContent)) {
                            target.removeAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "nil");
                        }
                    }
                    //for (let el of [...mutation.removedNodes]) {
                    //    Object.defineProperty(el, 'parentNode', { get: function () { return target } });
                    //    window.top.dispatchEvent(new xover.listener.Event('remove', { target: target }, el));
                    //};
                    if (mutation.removedNodes.length) {
                        //[...mutation.removedNodes].forEach(el => xover.listener.dispatchEvent(new xover.listener.Event('remove', { store: store, target: target }), el));
                        window.top.dispatchEvent(new xover.listener.Event('removeFrom', { removedNodes: mutation.removedNodes }, target))
                    }
                    window.top.dispatchEvent(new xover.listener.Event('change', { store: store, target: target, removedNodes: mutation.removedNodes, addedNodes: mutation.addedNodes }, target));

                    //if (mutation.attributeName) {
                    //    let attr = target instanceof Element && target.getAttributeNodeNS(mutation.attributeNamespace, mutation.attributeName);
                    //    if (!attr) {
                    //        //let target_copy = target.cloneNode();
                    //        //target_copy.createAttributeNS(mutation.attributeNamespace, mutation.attributeName);
                    //        //attr = target_copy.getAttributeNodeNS(mutation.attributeNamespace, mutation.attributeName);
                    //        attr = target.createAttributeNS(mutation.attributeNamespace, mutation.attributeName, null);
                    //    }
                    //}
                    //[...top.document.querySelectorAll('[xo-attribute]')].filter(el => el.store == self && el.scope && el.localName == mutation.attributeName && el.namespaceURI == mutation.attributeNamespace).reduce((stylesheets, stylesheet) => { if (!stylesheets.includes(stylesheet)) { stylesheets.push(stylesheet) }; return stylesheets }, []).forEach(stylesheet => stylesheet.render());
                    /*stores.filter(el => [...el.querySelectorAll('[xo-attribute]')].find(attrib => attrib.scope && attrib.scope.localName == mutation.attributeName && (attrib.scope.namespaceURI || '') == (mutation.attributeNamespace || ''))).forEach(stylesheet => stylesheet.render());*/
                }
                window.top.dispatchEvent(new xover.listener.Event('change', { store: store/*, removedNodes: mutation.removedNodes, addedNodes: mutation.addedNodes*/ }, store));

                if (mutationList.filter(mutation => mutation.target instanceof Document && mutation.type === 'childList' && [...mutation.removedNodes, ...mutation.addedNodes].find(el => el instanceof ProcessingInstruction)).length) {
                    self.render()
                }
                //if (target instanceof Document && target.childNodes.length === mutation.addedNodes.length && mutation.removedNodes.length === 0) {

                //}

                self.save && self.save();
            };

            const mutation_observer = new MutationObserver(callback);
            mutation_observer.observe(__document, config);
            const _observer = {}
            Object.defineProperty(self, 'observer', {
                get: function () {
                    return _observer;
                }
            })
            if (!self.observer.hasOwnProperty('disconnect')) {
                Object.defineProperty(self.observer, 'disconnect', {
                    value: function (ms) {
                        let mutations = mutation_observer.takeRecords()
                        mutation_observer.disconnect();
                        xover.delay(ms || 2).then(async () => {
                            mutation_observer.observe(__document, config);
                            mutations.length && callback(mutations);
                        });
                    },
                    writable: false, enumerable: false, configurable: false
                });
            }
            if (!self.observer.hasOwnProperty('connect')) {
                Object.defineProperty(self.observer, 'connect', {
                    value: function () {
                        mutation_observer.observe(__document, config);
                    },
                    writable: false, enumerable: false, configurable: false
                });
            }
        }
    })

    Object.defineProperty(this, 'documentElement', {
        get: function () {
            //if (__document.documentElement) {
            return __document.documentElement;
            //} else if (__document.source) {
            //    __document.store = store;
            //    return __document.fetch()/*new Promise(async resolve => {
            //        await this.initialize();
            //        resolve(__document.documentElement);
            //    })*/;
            //}
        }
    })

    Object.defineProperty(this, 'load', {
        value: async function (input) {
            throw (new Error("Load method is deprecated"));
        }
    });

    let _render_manager;
    Object.defineProperty(this, 'isRendering', {
        get: function () {
            return !!(_render_manager instanceof Promise);
        }
    });

    Object.defineProperty(this, 'reseed', {
        value: function () {
            var start_date = new Date();
            let data = this.document;
            return data.reseed();
            //        if (!data.documentElement) return data;
            //        let xsl = xover.xml.createDocument(`
            //<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xo="http://panax.io/xover">
            // <xsl:key name="xid" match="*" use="@xo:id" />
            // <xsl:template match="*|processing-instruction()|comment()">
            //  <xsl:copy>
            //   <xsl:copy-of select="@*[not(name()='xo:id')]"/>
            //   <xsl:apply-templates/>
            //  </xsl:copy>
            // </xsl:template>
            // <xsl:template match="*[count(key('xid',@xo:id)[1] | .)=1]">
            //  <xsl:copy>
            //   <xsl:copy-of select="@*"/>
            //   <xsl:apply-templates/>
            //  </xsl:copy>
            // </xsl:template>
            //</xsl:stylesheet>
            //`); // removes duplicate xids
            //        data = data.transform(xsl);
            //        let xsl_duplicates = xover.xml.createDocument(`
            //<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xo="http://panax.io/xover">
            // <xsl:key name="xid" match="*" use="@xo:id" />
            // <xsl:template match="/">
            //  <result>
            //   <xsl:apply-templates/>
            //  </result>
            // </xsl:template>
            // <xsl:template match="text()|processing-instruction()|comment()"/>
            // <xsl:template match="*"><xsl:apply-templates/></xsl:template>
            // <xsl:template match="*[@xo:id and count(key('xid',@xo:id)[1] | .)=2]">
            //  <xsl:copy>
            //   <xsl:copy-of select="@*"/>
            //  </xsl:copy>
            // </xsl:template>
            //</xsl:stylesheet>
            //`);
            //        let duplicate_id = (data.transform(xsl_duplicates).documentElement || {}).firstChild;
            //        if (duplicate_id) {
            //            console.warn("Document contains duplicate ids")
            //        }
            //        if (((arguments || {}).callee || {}).caller === this.reseed || !(data && data.selectSingleNode('/*') && data.selectSingleNode('//*[not(@xo:id)]'))) {
            //            return data;
            //        }

            //        data = data.reseed();
            //        data.href = __document.href;
            //        data.url = __document.url;
            //        __document = data;

            //        return this.reseed();
        },
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'addStylesheet', {
        value: async function (definition, refresh = false) {
            let style_definition, pi;
            let document = (this.document || this);
            if (definition instanceof ProcessingInstruction) {
                pi = definition;
            }
            else if (definition.constructor === {}.constructor) {
                definition = xover.json.merge({ type: 'text/xsl' }, definition);
                style_definition = xover.json.toAttributes(definition);
                pi = document.createProcessingInstruction('xml-stylesheet', style_definition);
                //pi.document.then(document => document.parentNode = store);
            } else {
                throw (new Error("Not a valid stylesheet"));
            }
            pi.store = store;
            Object.defineProperty(pi, 'parentNode', {
                value: store,
                writable: true, enumerable: false, configurable: true
            });
            if (!(_store_stylesheets.find(el => el.isEqualNode(pi)) || document.stylesheets.find(el => el.isEqualNode(pi)))) {
                _store_stylesheets.push(pi);
            }
            if (refresh) {
                store.render();
            }
            let stylesheet = this.getStylesheet(definition.href);
            return stylesheet;//.document.documentElement && stylesheet.document || stylesheet.document.fetch();
        },
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'removeStylesheet', {
        value: async function (definition_or_stylesheet) {
            let style_definition, pi;
            let document = (this.document || this);
            if (definition_or_stylesheet instanceof ProcessingInstruction) {
                pi = definition_or_stylesheet;
            }
            else if (definition_or_stylesheet.constructor === {}.constructor) {
                pi = this.document.getStylesheet(definition_or_stylesheet.href);
            } else {
                throw (new Error("Not a valid stylesheet"));
            }
            _store_stylesheets = _store_stylesheets.filter(el => !el.isEqualNode(pi));
            if (pi.ownerDocument.getStylesheet(pi)) {
                pi.remove();
            }
        },
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'stylesheets', {
        get: function () {
            let stylesheets_nodes = _store_stylesheets.concat(__document.stylesheets);
            Object.defineProperty(stylesheets_nodes, 'getDocuments', {
                value: function () {
                    let docs = []
                    for (let stylesheet of this) {
                        docs.push(stylesheet.document);
                    }
                    return docs;
                },
                writable: false, enumerable: false, configurable: false
            });

            Object.defineProperty(stylesheets_nodes, 'toJSON', {
                value: function () {
                    let json = []
                    for (let stylesheet of this) {
                        json[stylesheet.href] = stylesheet
                    }
                    return json;
                },
                writable: false, enumerable: false, configurable: false
            });

            return new Proxy(stylesheets_nodes, {
                get: function (target, prop) { //para búsquedas por href
                    if (prop in target) {
                        return target[prop];
                    }
                    return target.find(stylesheet => stylesheet.href == prop);
                }
            })
            return stylesheets_nodes
        }
    });

    Object.defineProperty(this, 'getStylesheet', {
        value: function (href) {
            return store.stylesheets.find(stylesheet => stylesheet.href === href)
        },
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'toString', {
        value: function (href) {
            let doc = __document.cloneNode(true);
            _store_stylesheets.reverse().forEach(stylesheet => doc.prepend(stylesheet));
            return doc.toString();
        },
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'toClipboard', {
        value: function (href) {
            let doc = __document.cloneNode(true);
            _store_stylesheets.reverse().forEach(stylesheet => doc.prepend(stylesheet));
            return doc.toClipboard();
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(this, 'fetch', {
        value: async function () {
            if (__document.fetch) {
                try {
                    await __document.fetch()
                } catch (e) {
                    return Promise.reject(e);
                }
            }
            await this.initialize();
            this.reseed();
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(this, 'initialize', {
        value: async function () {
            _store_stylesheets.filter(stylesheet => stylesheet.role == 'init' && !__document.selectSingleNode(`comment()[.="Initialized by ${stylesheet.href}"]`)).forEach(async stylesheet => {
                let _document_stylesheet = __document.stylesheets[stylesheet.href];
                if (_document_stylesheet) {
                    _document_stylesheet.replaceBy(__document.createComment('Initialized by ' + stylesheet.href));
                }

                let new_document = __document.transform(await stylesheet.document.fetch());
                if ((((new_document.documentElement || {}).namespaceURI || '').indexOf("http://www.w3.org") == -1)) {
                    /*La transformación no debe regresar un html ni otro documento del estándar*/
                    this.document = new_document;
                } else {
                    delete stylesheet["role"];
                    __document.addStylesheet(stylesheet);
                    console.warn("Initial transformation shouldn't yield a html or any other document from the w3 standard.");
                }
                store.save();
            });
        },
        writable: false, enumerable: false, configurable: false
    });

    if (!__document) throw (new Error("__document is empty"));
    if (typeof (__document) == 'string') {
        __document = xover.xml.createDocument(__document)
    }

    Object.defineProperty(this, 'render', {
        value: async function () {
            //let before = new xover.listener.Event('beforeRender', this);
            //xover.listener.dispatchEvent(before, this);
            //if (before.cancelBubble || before.defaultPrevented) return;
            if (xover.init.status != 'initialized') {
                await xover.init();
            }
            _render_manager = _render_manager || xover.delay(1).then(async () => {
                let tag = self.tag;
                if (!__document.documentElement) {
                    if (!xover.site.sections[tag]) {
                        await xover.sources['loading.xslt'].render();
                    }
                    try {
                        await store.fetch();
                    } catch (e) {
                        return Promise.reject(e);
                    }
                    if (!__document.documentElement) {
                        return Promise.reject(``); //No document body for ${tag}
                    }
                    let source = __document.source;
                    source && source.save && source.save();
                }
                //if (!(_store_stylesheets.filter(stylesheet => stylesheet.role != 'init').length || __document.stylesheets.length)) {
                //    store.addStylesheet({ href: store.tag.substring(1).split(/\?/, 1).shift() + '.xslt', target: "main" })
                //}
                await store.sources.load();
                let isActive = self.isActive
                let active_tag = xover.site.active;
                let active_store = xover.stores.active;

                let stylesheets = xover.site.sections.filter(el => el.store && el.store === self);
                stylesheets.forEach((el) => el.render());

                let doc = __document;//.cloneNode(true); //Now is not cloned to keep reference of the original document
                //_store_stylesheets.reverse().forEach(stylesheet => doc.prepend(stylesheet));
                doc.store = store;
                //await (async (pending_stylesheets) => pending_stylesheets.length && await doc.render(pending_stylesheets))(((stylesheets) => doc.stylesheets.filter(stylesheet => !stylesheets.includes(stylesheet.href)))(stylesheets.map(el => el.getAttribute("xo-stylesheet"))));
                return doc.render([..._store_stylesheets, ...doc.stylesheets].distinct());
            }).then(async () => {
                let tag = self.tag;
                let targetDocument = ((document.activeElement || {}).contentDocument || document);
                let dom = targetDocument.querySelector(`[xo-store="${tag}"]`)
                window.top.dispatchEvent(new xover.listener.Event('domLoaded', { target: dom, initiator: this }));
                let active_store = xover.stores.active;
                return Promise.resolve(self)
            }).catch((e) => {
                let tag = self.tag;
                e = e || {}
                if (e instanceof Response || e instanceof Error || typeof (e) === 'string') {
                    if ([401].includes(e.status)) {
                        console.error(e.statusText)
                    } else {
                        return Promise.reject(e);
                    }
                } else {
                    console.log(`Couldn't render store: ${tag}`)
                    //e = e instanceof Error && e || e.message || e || `Couldn't render store ${tag}`
                    return Promise.reject();
                }
                return;
            }).finally(async () => {
                xover.site.restore();
                let loading = window.document.querySelector('[xo-stylesheet="loading.xslt"]')
                loading && loading.remove();
                _render_manager = undefined;
            });
            return _render_manager;
        },
        writable: true, enumerable: false, configurable: false
    });

    for (let prop of ['$', '$$', 'cloneNode', 'normalizeNamespaces', 'contains', 'querySelector', 'querySelectorAll', 'selectSingleNode', 'selectNodes', 'select', 'selectFirst', 'evaluate', 'getStylesheets', 'createProcessingInstruction', 'firstElementChild', 'insertBefore', 'resolveNS', 'xml']) {
        let prop_desc = Object.getPropertyDescriptor(__document, prop);
        if (!prop_desc) {
            continue
        } else if (prop_desc.value) {
            Object.defineProperty(this, prop, {
                value: function () { return __document[prop].apply(__document, arguments) }
                , enumerable: true, configurable: false
            });
        } else if (prop_desc.get) {
            Object.defineProperty(this, prop, {
                get: function () { return __document[prop] }
                , enumerable: true, configurable: false
            });
        }

    }
    this.document = __document;
    _tag = config && config['tag'] || this.generateTag.call(this, __document) || xover.cryptography.generateUUID();
    _tag = _tag.split(/\?/)[0];
    //this.reseed();
    xover.manifest.getSettings(this, 'stylesheets').flat().forEach(stylesheet => store.addStylesheet(stylesheet, false));
    window.top.dispatchEvent(new xover.listener.Event('storeLoaded', { store: this }, this));
    xover.stores[_tag] = this;
    return this;
}

xover.Store.prototype.onLoad = function () {
    console.log("Do nothing");
}

Object.defineProperty(xover.Store.prototype, 'fetch', {
    value: async function (input) {
        _fetch_url = (_fetch_url || input);
        if (!_fetch_url) {
            throw (new Error("No url initialized."));
        }
        let data = await xover.fetch(_fetch_url).then(response => response.body);
        this.document = data;
        if (xover.stores.active === this) {
            this.render(/*true*/);
        }
    }
})

Object.defineProperty(xover.Store.prototype, 'isActive', {
    get: function () {
        return (this === xover.stores.active || xover.site.activeTags().includes(this.tag) || this.isRendered || !window.document.querySelector("[xo-store]"));
    },
    set: function (input) {
        if (input) {
            history.state.active = this.tag;
        } else {
            delete history.state.active;
        }
    }
});

Object.defineProperty(xover.Store.prototype, 'isRendered', {
    get: function () {
        return !!document.querySelector(`[xo-store="${this.tag}"]`);
    }
});

Object.defineProperty(xover.Store.prototype, 'find', {
    value: function (reference) {
        if (!reference) return null;
        var ref = reference;
        if (typeof (reference) == "string") {
            ref = this.document.selectSingleNode('//*[@xo:id="' + reference + '" ]')
            if (!ref) {
                ref = this.document.selectSingleNode(reference)
            }
        }
        if (!ref) return;
        var exists = false;
        var return_value;
        if (this.document.contains(ref) || ref.nodeType == 2 && this.document.contains(ref.selectSingleNode('..'))) {
            return ref;
        }
        if (ref.nodeType == 2) {
            return this.document.selectSingleNode('//*[@xo:id="' + (ref.ownerElement || document.createElement('p')).getAttributeNS("http://panax.io/xover", "id") + '"]/@' + ref.name);
        } else {
            return (this.document.selectSingleNode('//*[@xo:id="' + (ref.documentElement || ref instanceof Element && ref || document.createElement('p')).getAttributeNS("http://panax.io/xover", "id") + '"]')); // || xover.stores.active.selectSingleNode(xover.xml.getXpath(ref))
        }
    },
    writable: false, enumerable: false, configurable: false
});

xover.Store.prototype.generateTag = function (document) {
    if (!(document && document.documentElement)) {
        return xover.cryptography.generateUUID()
    }
    return (document.documentElement && (document.documentElement.getAttributeNS("http://panax.io/xover", "tag") || document.documentElement.getAttributeNS("http://panax.io/xover", "id") || document.documentElement.localName.toLowerCase())).split(/^#/).pop();
}

xover.xml.getAttributeParts = function (attribute = "") {
    let name, prefix;
    if (attribute instanceof Attr) {
        prefix = attribute.prefix;
        name = attribute.localName;
    } else {
        let attribute_name = attribute.split(':', 2);
        name = attribute_name.pop();
        prefix = attribute_name.pop();
    }
    return { "prefix": prefix, "name": name }
}

xover.post = {}
xover.post.to = async function (request, payload, settings = {}) {
    settings["body"] = payload;
    return xover.fetch(request, settings);
}

xover.xml.fromCSV = function (csv, settings = {}) {
    let { dataset = "dataset", row = "row", cell = "cell" } = settings;
    let xml = xover.xml.createDocument(`<${dataset}><${row}>` + csv.replace(new RegExp('(,|\n|^)("(?:(?:"")*[^"]*)*"|[^",\n]*|(?:\n|$))', 'g'), `</${row}>$1<${row}><${cell}>$2</${cell}>`).replace(new RegExp(`</${row}>,<${row}>`, 'ig'), '').replace(new RegExp(`<(${cell})>"([^"]*)"</\\1>`, 'ig'), `<$1>$2</$1>`) + `</${row}></${dataset}>`);
    xml.selectNodes('*/*[1]').removeAll();
    return xml
}

xover.xml.fromJSON = function (json) {
    if (typeof (json) == "string") {
        json = json.replace(/\r\n/g, "")
    } else if (json.constructor == {}.constructor || json.constructor == [].constructor) {
        json = JSON.stringify(json);
    } else {
        throw (new Error("Not a valid json"));
    }
    let raw_xson = xover.xml.createDocument(
        xover.string.replace(
            xover.string.replace(
                xover.string.replace(
                    xover.string.replace(
                        xover.string.replace(
                            xover.string.replace(
                                xover.string.replace(
                                    xover.string.replace(
                                        xover.string.replace(
                                            xover.string.replace(xover.string.replace(xover.string.replace(xover.string.replace(json, '\\t', '<t/>', 1), '\\n', '<r/>', 1), '\\r', '<r/>', 1), ',', '<c/>', 1)
                                            , '&', '&amp;')
                                        , '\\(.)', '<e>$1</e>', 1)
                                    , '[', '<l>')
                                , ']', '</l>')
                            , '{', '<o>')
                        , '}', '</o>')
                    , '\\s', '<s/>', 1)
                , '"([^"]+?)"\\:', '<a>$1</a>', 1)
            , '<l>([^<]+)</l>', '<l>$1</l>', 1)
    );

    let reformated_xson = raw_xson.transform(xover.xml.createDocument(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns="" version="1.0" id="raw_json_compatibility"><xsl:variable name="node_name">olsc</xsl:variable><xsl:variable name="translate-o">{[ ,</xsl:variable><xsl:variable name="translate-c">}] </xsl:variable><xsl:template match="/"><xsl:apply-templates></xsl:apply-templates></xsl:template><xsl:template match="*" mode="value"><xsl:copy><xsl:copy-of select="@*"></xsl:copy-of><xsl:apply-templates></xsl:apply-templates></xsl:copy></xsl:template><xsl:template match="o|l|c" mode="value"><xsl:param name="is_string" select="false()"></xsl:param><xsl:value-of select="translate(name(),$node_name,$translate-o)"></xsl:value-of><xsl:apply-templates select="(text()|*)[1]" mode="value"><xsl:with-param name="is_string" select="$is_string"></xsl:with-param></xsl:apply-templates><xsl:value-of select="translate(name(),$node_name,$translate-c)"></xsl:value-of><xsl:apply-templates select="(following-sibling::text()|following-sibling::*)[1]" mode="value"><xsl:with-param name="is_string" select="$is_string"></xsl:with-param></xsl:apply-templates></xsl:template><xsl:template match="s" mode="value"><xsl:param name="is_string" select="false()"></xsl:param><xsl:value-of select="' '"></xsl:value-of><xsl:if test="$is_string"><xsl:apply-templates select="(following-sibling::text()|following-sibling::*)[1]" mode="value"><xsl:with-param name="is_string" select="$is_string"></xsl:with-param></xsl:apply-templates></xsl:if></xsl:template><xsl:template match="r|f" mode="value"><xsl:param name="is_string" select="false()"></xsl:param><xsl:text></xsl:text><xsl:apply-templates select="(text()|*)[1]" mode="value"><xsl:with-param name="is_string" select="$is_string"></xsl:with-param></xsl:apply-templates><xsl:apply-templates select="(following-sibling::text()|following-sibling::*)[1]" mode="value"><xsl:with-param name="is_string" select="$is_string"></xsl:with-param></xsl:apply-templates></xsl:template><xsl:template match="e" mode="value"><xsl:param name="is_string" select="false()"></xsl:param><xsl:text>\</xsl:text><xsl:value-of select="text()"></xsl:value-of><xsl:apply-templates select="(following-sibling::text()|following-sibling::*)[1]" mode="value"><xsl:with-param name="is_string" select="$is_string"></xsl:with-param></xsl:apply-templates></xsl:template><xsl:template match="text()" mode="value"><xsl:param name="is_string" select="false()"></xsl:param><xsl:copy></xsl:copy><xsl:if test="$is_string and not(substring(.,string-length(.),1)='&quot;')"><xsl:apply-templates select="(following-sibling::text()|following-sibling::*)[1]" mode="value"><xsl:with-param name="is_string" select="$is_string"></xsl:with-param></xsl:apply-templates></xsl:if></xsl:template><xsl:template match="text()[substring(.,1,1)='&quot;']" mode="value"><xsl:param name="is_string" select="false()"></xsl:param><xsl:copy></xsl:copy><xsl:if test="not(substring(.,string-length(.),1)='&quot;')"><xsl:apply-templates select="(following-sibling::text()|following-sibling::*)[1]" mode="value"><xsl:with-param name="is_string" select="true()"></xsl:with-param></xsl:apply-templates></xsl:if></xsl:template><xsl:template match="l/text()"><xsl:element name="v"><xsl:value-of select="."/></xsl:element></xsl:template><xsl:template match="l"><xsl:copy><xsl:copy-of select="@*"></xsl:copy-of><xsl:apply-templates select="o|text()"></xsl:apply-templates></xsl:copy></xsl:template><xsl:template match="o"><xsl:copy><xsl:copy-of select="@*"></xsl:copy-of><xsl:apply-templates select="a"></xsl:apply-templates></xsl:copy></xsl:template><xsl:template match="a"><xsl:variable name="following" select="(following-sibling::text()|following-sibling::*[not(self::f or self::r or self::c or self::s)])[1]"></xsl:variable><xsl:copy><xsl:element name="n"><xsl:value-of select="text()"></xsl:value-of></xsl:element><xsl:choose><xsl:when test="$following/self::o or $following/self::l"><xsl:apply-templates select="$following"></xsl:apply-templates></xsl:when><xsl:otherwise><xsl:element name="v"><xsl:apply-templates select="$following" mode="value"></xsl:apply-templates></xsl:element></xsl:otherwise></xsl:choose></xsl:copy></xsl:template></xsl:stylesheet>`));

    let xson = reformated_xson.transform(xover.xml.createDocument(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xson="http://panax.io/xson" xmlns="" version="1.0" id="PrettifyJSON"><xsl:variable name="invalidChars" select="'$:/@ '"></xsl:variable><xsl:template match="/"><xsl:apply-templates mode="raw-to-xson"></xsl:apply-templates></xsl:template><xsl:template match="*" mode="raw-to-xson"><xsl:apply-templates mode="raw-to-xson"></xsl:apply-templates></xsl:template><xsl:template match="o|l" mode="raw-to-xson"><xsl:apply-templates mode="raw-to-xson"></xsl:apply-templates></xsl:template><xsl:template match="l/v" mode="raw-to-xson"><xsl:element name="xson:item"><xsl:apply-templates mode="raw-to-xson"></xsl:apply-templates></xsl:element></xsl:template><xsl:template match="a" mode="raw-to-xson"><xsl:variable name="name"><xsl:choose><xsl:when test="number(translate(n,'&quot;',''))=translate(n,'&quot;','')"><xsl:value-of select="concat('@',translate(n,'&quot;',''))"></xsl:value-of></xsl:when><xsl:otherwise><xsl:value-of select="translate(translate(n,'&quot;',''),$invalidChars,'@@@@@')"></xsl:value-of></xsl:otherwise></xsl:choose></xsl:variable><xsl:element name="{translate($name,'@','_')}"><xsl:if test="contains($name,'@')"><xsl:attribute name="xson:originalName"><xsl:value-of select="translate(n,'&quot;','')"></xsl:value-of></xsl:attribute></xsl:if><xsl:if test="l"><xsl:attribute name="xsi:type">xson:array</xsl:attribute></xsl:if><xsl:apply-templates select="*" mode="raw-to-xson"></xsl:apply-templates></xsl:element></xsl:template><xsl:template match="text()" mode="raw-to-xson"><xsl:value-of select="."></xsl:value-of></xsl:template><xsl:template match="text()[starts-with(.,'&quot;')]" mode="raw-to-xson"><xsl:value-of select="substring(.,2,string-length(.)-2)"></xsl:value-of></xsl:template><xsl:template match="text()[.='null']|*[.='']" mode="raw-to-xson"></xsl:template><xsl:template match="text()[.='null']" mode="raw-to-xson"><xsl:attribute name="xsi:nil">true</xsl:attribute></xsl:template><xsl:template match="n" mode="raw-to-xson"></xsl:template><xsl:template match="a[v='true' or v='false']/n" mode="raw-to-xson"><xsl:attribute name="xsi:type">boolean</xsl:attribute></xsl:template><xsl:template match="e" mode="raw-to-xson"><xsl:value-of select="@v"></xsl:value-of></xsl:template><xsl:template match="a[number(v)=v]/n" mode="raw-to-xson"><xsl:attribute name="xsi:type">numeric</xsl:attribute></xsl:template><xsl:template match="a[starts-with(v,'&quot;')]/n" mode="raw-to-xson"><xsl:attribute name="xsi:type">string</xsl:attribute></xsl:template><xsl:template match="a[l]/n" mode="raw-to-xson"><xsl:attribute name="xsi:type">xson:array</xsl:attribute></xsl:template><xsl:template match="a[o]/n" mode="raw-to-xson"><xsl:attribute name="xsi:type">xson:object</xsl:attribute></xsl:template><xsl:template match="o[not(preceding-sibling::n)]" mode="raw-to-xson"><xsl:element name="xson:object"><xsl:apply-templates mode="raw-to-xson"></xsl:apply-templates></xsl:element></xsl:template><xsl:template match="l[not(preceding-sibling::n)]" mode="raw-to-xson"><xsl:element name="xson:array"><xsl:apply-templates mode="raw-to-xson"></xsl:apply-templates></xsl:element></xsl:template></xsl:stylesheet>`));

    xson.normalizeNamespaces();
    return xson;
}

xover.json.merge = function () {
    var response = (arguments[0] || {})
    for (let a = 1; a < arguments.length; a++) {
        var object = arguments[a]
        if (object && object.constructor == {}.constructor) {
            for (let key in object) {
                if (object[key] && object[key].constructor == {}.constructor) {
                    response[key] = xover.json.merge(response[key], object[key]);
                } else {
                    response[key] = object[key];
                }
            }
        }
    }
    return response;
}

xover.json.difference = function () {
    var response = (arguments[0] || {})
    for (let a = 1; a < arguments.length; a++) {
        var object = arguments[a]
        if (object && object.constructor == {}.constructor) {
            for (let key in object) {
                if (response.hasOwnProperty(key)) {
                    delete response[key];
                }
            }
        }
    }
    return response;
}

xover.json.toAttributes = function (json) {
    json = Object.entries(json).reduce((filtered, [key, value]) => { if (value !== undefined) { filtered[key] = value; } return filtered; }, {})
    let attribs = new URLSearchParams(json);
    //let dummy = document.createElement("p");
    //[...attribs.entries()].forEach(([attr, value]) => dummy.setAttribute(attr, value));
    //return dummy.outerHTML.replace(/^<p\s|><\/p>$/g, '') //TODO: Evaluate what approach is better
    return [...attribs.entries()].reduce((params, entry) => { params.push(`${entry[0]}=${JSON.stringify(entry[1])}`); return params }, []).join(" ")
}

xover.json.fromAttributes = function (attributes) {
    return JSON.parse('{' + (attributes.match(/(\w+)=(["'])([^\2]*?)\2/ig) || []).join(", ").replace(/(\w+)=(["'])([^\2]*?)\2/ig, '"$1":$2$3$2') + '}')
}

//xover.json.fromAttributes = function (attributes) { //Version with createNode, witch is slower.
//    let json = {}
//    let node = xover.xml.createNode(`<node ${attributes} />`);
//    [...node.attributes].map(attr => json[attr.nodeName] = attr.nodeValue);
//    return json
//}

xover.xml.getXpath = function (node) {
    var xpath = '';
    xpath = (node.firstElementChild || node).nodeName;
    if (node.parentElement) {
        xpath = xover.xml.getXpath(node.parentElement) + '/' + xpath;
    }
    return xpath;
}

xover.data.search = function (xpath, dataset) {
    var ref;
    var dataset = (dataset || xover.stores.active || xover.Store().document)
    if (typeof (xpath) == "string") {
        ref = dataset.selectSingleNode(xpath)
    }
    return ref;
}

xover.data.find = function (ref, dataset) {
    var dataset = (dataset || xover.stores.active || xover.Store())
    if (typeof (ref) == "string") {
        ref = dataset.selectSingleNode('//*[@xo:id="' + ref + '" ]')
    }
    if (!ref) return;
    var exists = false;
    var return_value;
    if (dataset.contains(ref) || ref.nodeType == 2 && dataset.contains(ref.selectSingleNode('..'))) {
        return ref;
    }
    if (ref.nodeType == 2) {
        return dataset.selectSingleNode('//*[@xo:id="' + (ref.ownerElement || document.createElement('p')).getAttributeNS("http://panax.io/xover", "id") + '"]/@' + ref.name);
    } else {
        return (dataset.selectSingleNode('//*[@xo:id="' + (ref.documentElement || ref || document.createElement('p')).getAttributeNS("http://panax.io/xover", "id") + '"]') || xover.stores.active.selectSingleNode(xover.xml.getXpath(ref)));
    }
}

xover.data.deepFind = function (ref) {
    var target = xover.stores.active.find(ref);
    if (target) {
        return target;
    }
    //xover.stores.filter((nombre, document) => document.selectSingleNode(`//*[@xo:id="${typeof (ref) == 'string' ? ref : ref.getAttributeNS("http://panax.io/xover", "id")}"]`))
    for (let xDocument in xover.stores) {
        target = xover.stores[xDocument].find(ref);
        if (target) {
            return target;
        }
    }
    return target;
}

xover.dom.allowDrop = function (ev) {
    ev.preventDefault();
}

xover.dom.drag = function (ev) {
    ev.dataTransfer.setData("text", ev.target.id);
}

xover.dom.drop = function (ev) {
    ev.preventDefault();
    var data = ev.dataTransfer.getData("text");
    ev.target.appendChild(document.getElementById(data));
}

xover.storage.clearCache = function (document_name) {
    if (typeof (Storage) !== "undefined") {
        localStorage.clear();
    } else {
        console.error('Storage is not supported by your browser');
    }
}

xover.storage.setKey = function (key, value) {
    if (typeof (Storage) !== "undefined") {
        let session_id = (xover.session.network_id && `${xover.session.network_id}/` || `${location.hostname}${location.pathname.replace(/[^/]+$/, "")}`);
        if (!key) return;
        key = `${session_id}${key}`;
        if (value === undefined) {
            localStorage.removeItem(key);
        } else if (value instanceof Attr) {
            localStorage.setItem(key, JSON.stringify({ attribute: value.name, value: value.value, target: (value.selectSingleNode("../@xo:id") || {}).value, parent: (value.selectSingleNode("../../@xo:id") || {}).value, preceding_sibling: (value.selectSingleNode("../preceding-sibling::*/@xo:id") || {}).value }));
        } else if ((value instanceof Node || value instanceof xover.Store) && value.toString) {
            localStorage.setItem(key, JSON.stringify(value.toString()));
        } else if (value instanceof Node && value.outerHTML) {
            localStorage.setItem(key, JSON.stringify(value.outerHTML));
        } else {
            localStorage.setItem(key, JSON.stringify(value));
        }
    } else {
        console.error('Storage is not supported by your browser')
    }
}

xover.storage.getKey = function (key) {
    //if (!eval(xover.storage.enabled) && key != 'xover.storage.enabled') return;
    if (typeof (Storage) !== "undefined") {
        let session_id = (xover.session.network_id && `${xover.session.network_id}/` || `${location.hostname}${location.pathname.replace(/[^/]+$/, "")}`);
        var document = JSON.parse(localStorage.getItem(`${session_id}${key}`));
        if (document) {
            return document;
        }
    } else {
        console.error('Storage is not supported by your browser')
    }
}

xover.network = {}
Object.defineProperty(xover.network, 'broadcast', {
    value: function (package) {
        if (event.srcEvent instanceof StorageEvent) return;
        let json_rpc, json_rpc_params;
        if (package instanceof Attr) {
            json_rpc_params = { attribute: package.name, namespace: package.namespaceURI, value: package.value, target: package.parentNode.getAttribute("xo:id"), "store": (package.ownerDocument.store || {}).tag };
            json_rpc = xover.network.createCall("set", json_rpc_params)
        } else if ((package instanceof Node || package instanceof xover.Store) && package.toString) {
            if (package.parentElement) {
                json_rpc_params = { value: package.toString(), namespace: package.namespaceURI, target: (package.parentNode.selectSingleNode("@xo:id") || {}).value, parent: (package.selectSingleNode("../@xo:id") || {}).value, preceding_sibling: (package.previousElementSibling || document.createElement("p")).getAttribute("xo:id"), "store": (package.ownerDocument.store || {}).tag };
                json_rpc = xover.network.createCall("set", json_rpc_params)
            } else {
                json_rpc = xover.network.createCall("remove", { "target": package.getAttribute("xo:id"), "store": (package.ownerDocument.store || {}).tag })
            }
        } else if (package.constructor === {}.constructor && package.hasOwnProperty("jsonrpc")) {
            json_rpc = package
        } else {
            json_rpc = xover.network.createCall("apply", package)
        }
        xover.storage.setKey("rpc:json", json_rpc);
        xover.storage.setKey("rpc:json", undefined);
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.network, 'connect', {
    value: function (input) {
        xover.session.network_id = (input || xover.session.network_id || xover.cryptography.generateUUID());
        return xover.session.network_id;
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.network, 'createCall', {
    value: function (method, params) {
        return { "jsonrpc": "2.0", "method": method, "params": params, "id": xover.cryptography.generateUUID() }
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.network, 'createResponse', {
    value: function (id, response, error_code = 500) {
        if (error_code) {
            return { "jsonrpc": "2.0", "error": { "code": error_code, "message": response }, "id": id }
        } else {
            return { "jsonrpc": "2.0", "result": response, "id": xover.cryptography.generateUUID() }
        }
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.network, 'id', {
    get: function () {
        return xover.session.network_id;
    }
});

Object.defineProperty(xover.network, 'disconnect', {
    value: function () {
        xover.session.network_id = undefined;
        return xover.session.network_id;
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xover.network, 'listener', {
    value: function (event) {
        if (!event) { event = window.event; }
        if (event.newValue === null) return;
        let session_id = (xover.session.network_id && `${xover.session.network_id}/` || `${location.hostname}${location.pathname.replace(/[^/]+$/, "")}`);
        if (event.key.match(new RegExp(`^${session_id}`, 'i'))) {
            let key = event.key.replace(new RegExp(`^${session_id}`, 'i'), '');
            let new_value = JSON.parse(event.newValue);
            if (["network_id"].includes(key)) return;
            if (key === "rpc:json") {
                if (new_value.method) {
                    let store = new_value.params.store;
                    let target_id = new_value.params.target;
                    let action = new_value.method;
                    let ref_node;
                    switch (action) {
                        case 'remove':
                            ref_node = xover.stores[store].find(target_id);
                            ref_node && ref_node.remove();
                            break;
                        case 'insert':
                            ref_node = xover.stores[store].find(target_id);
                            ref_node && ref_node.insertAfter(xover.xml.createNode(target_node.value), target_node.find(new_value.find(new_value.params.preceding_sibling)));
                            break;
                        case 'set':
                            let attribute = new_value.params.attribute;
                            let namespace = new_value.params.namespace;
                            if (new_value.params.attribute) {
                                ref_node = xover.stores[store].find(target_id);
                                ref_node && ref_node.setAttributeNS(namespace, attribute, new_value.params.value);
                            } else {
                                let new_node = xover.xml.createNode(new_value.params.value);
                                ref_node = xover.stores[store].find(new_value.params.preceding_sibling);
                                if (ref_node) {
                                    ref_node.appendAfter(new_node)
                                    break;
                                }
                                ref_node = xover.stores[store].find(new_value.params.parent);
                                if (ref_node) {
                                    ref_node.appendChild(new_node)
                                    break;
                                }
                                if (!ref_node) {

                                }
                            }
                            break;
                        default:
                            console.error("No se pudo sincronizar la solicitud")
                    }
                    if (!ref_node) {
                        xover.network.broadcast(xover.network.createResponse(new_value.id, "No se pudo completar el proceso"));
                    }
                } else {
                    window.top.dispatchEvent(new xover.listener.Event('rpcResponse', new_value));
                }
            } else {
                xover.session[key] = new_value;
            }
        }
    },
    writable: false, enumerable: false, configurable: false
});

if (window.addEventListener) {
    window.addEventListener("storage", xover.network.listener, false);
} else {
    window.attachEvent("onstorage", xover.network.listener);
};

//xover.listener.on('beforeRemoveHTMLElement', function ({ target }) {
//    let xo_store = target.getAttribute("xo-store");
//    if (xo_store) {
//        delete xover.stores[xo_store];
//    } else {
//        if (target.classList && target.classList.contains("loading") || ["alert", "alertdialog"].includes(String(target.role).toLowerCase())) {
//            let store = target.store;
//            if (store && (store.state.submitting || store.state.busy)) {
//                event.preventDefault();
//                [store.stylesheets['loading.xslt']].removeAll();
//            };
//        }
//    }
//})

//xover.listener.on('remove', function ({ target }) { //Se quita para que no borre stores accidentalmente (si se borra el nodo raíz). Si la intención es borrar el store o el nodo, mejor realizar un element.scope.remove()
//    let scope = target.scope; 
//    if (scope instanceof Element) {
//        scope && scope.remove();
//    }
//})

xover.listener.keypress = function (e = {}) {
    xover.listener.keypress.ctrlKey = e.ctrlKey;
    xover.listener.keypress.shiftKey = e.shiftKey;
    xover.listener.keypress.altKey = e.altKey;
    xover.listener.keypress.tabKey = (e.keyCode == 9);
    xover.dom.triggeredByTab = (xover.dom.triggeredByTab || xover.listener.keypress.tabKey);
    xover.listener.keypress.escKey = (e.keyCode == 27);
    if (xover.debug["xover.listener.keypress"]) {
        console.log(String.fromCharCode(e.keyCode) + " --> " + e.keyCode)
    }
}

xover.listener.keypress.last_key = undefined;
xover.listener.keypress.streak_count = 0;

document.onkeydown = function (event) {
    if (![9].includes(event.keyCode)) {
        xover.delay(1).then(() => {
            xover.site.save(event.srcElement.selector);
        })
    }
    if (event.keyCode == xover.listener.keypress.last_key) {
        ++xover.listener.keypress.streak_count;
    } else {
        xover.listener.keypress.last_key = event.keyCode;
        xover.listener.keypress.streak_count = 1;
    }
    if (xover.debug["xover.listener.keypress.keydown"]) {
        if (!xover.debug["xover.listener.keypress"]) {
            console.log("key pressed: " + event.keyCode)
        }
        console.log("xover.listener.keypress.streak_count: " + xover.listener.keypress.streak_count)
    }
    xover.listener.keypress(event);
    if (xover.listener.keypress.altKey || xover.listener.keypress.shiftKey || xover.listener.keypress.ctrlKey) {
        if (this.keyInterval != undefined) {
            window.clearTimeout(this.keyInterval);
            this.keyInterval = undefined;
        }
        this.keyInterval = window.setTimeout(function () {
            xover.listener.keypress();
            this.keyInterval = undefined;
        }, 1000);
        return;
    } //if combined with alt/shift/ctrl keys 
    // in grids, this function will allow move up and down between elements
    var srcElement = event.srcElement;
    if (event.keyCode == 40 && !(event.srcElement instanceof HTMLTextAreaElement || srcElement.hasAttribute("contenteditable"))) {
        if (srcElement.nodeName.toLowerCase() == 'select' && (srcElement.size || xover.browser.isIE() || xover.browser.isEdge())) return;
        currentNode = srcElement.source;
        if (!currentNode) return false;
        nextNode = currentNode.selectSingleNode('../following-sibling::*[not(@xo:deleting="true")][1]/*[local-name()="' + currentNode.nodeName + '"]')
        if (nextNode) {
            let nextElement = document.getElementById(nextNode.getAttribute('xo:id'));
            nextElement && nextElement.focus();
        }
        event.preventDefault();
    } else if (event.keyCode == 38 && !(event.srcElement instanceof HTMLTextAreaElement || srcElement.hasAttribute("contenteditable"))) {
        if (srcElement.nodeName.toLowerCase() == 'select' && (srcElement.size || xover.browser.isIE() || xover.browser.isEdge())) return;
        currentNode = srcElement.source;
        if (!currentNode) return false;
        nextNode = currentNode.selectSingleNode('../preceding-sibling::*[not(@xo:deleting="true")][1]/*[local-name()="' + currentNode.nodeName + '"]')
        if (nextNode) {
            let nextElement = document.getElementById(nextNode.getAttribute('xo:id'));
            nextElement && nextElement.focus();
        }
        event.preventDefault();
    }
    if (srcElement.nodeName.toLowerCase() == 'select') {//disable behaviour that changes options with arrows, preventing unwanted changes
        var key = event.which || event.keyCode;
        if (key == 37) {
            event.preventDefault();
        } else if (key === 39) {
            event.preventDefault();
        }
    }
    //if ((document.activeElement || {}).value) {
    //    xover.dom.activeElementCaretPosition = parseFloat(String(xover.dom.getCaretPosition(document.activeElement)).split(",").pop()) + 1;
    //}
};

document.onkeyup = function (e) {
    xover.listener.keypress.last_key = e.keyCode;
    xover.listener.keypress(e);
    window.setTimeout(function () { xover.listener.keypress(e); }, 300);
    if (e.key == 'Escape') {
        [...document.querySelectorAll('dialog:not([open])')].removeAll()
    }
};

// TODO: Modificar listeners para que funcion con el método de XOVER
xover.dom.beforeunload = function (e) {
    history.replaceState(Object.assign({}, history.state), {}, location.pathname + location.search + (location.hash || ''));
    //let stores = await xover.storehouse.sources;
    //for (let hashtag in xover.stores) {
    //    console.log("Saving " + hashtag)
    //    stores.put((xover.stores[hashtag].initiator || xover.stores[hashtag]), hashtag)
    //    //xover.session.setKey(hashtag, (xover.stores[hashtag].initiator || xover.stores[hashtag]));
    //}
    ////history.replaceState(history.state || {}, {}, (window.top || window).location.hash || '/');
    //event.returnValue = `Are you sure you want to leave?`;

    //console.log("checking if we should display confirmation dialog");
    //var shouldCancel = false;
    //if (shouldCancel) {
    //    console.log("displaying confirmation dialog");
    //    e.preventDefault();
    //    e.returnValue = false;
    //}
};

var eventName = xover.browser.isIOS() ? "pagehide" : "beforeunload";

window.addEventListener(eventName, xover.dom.beforeunload);

xover.dom.print = function () {
    var iframes = document.querySelectorAll('iframe');

    if (iframes) {
        for (let f = 0; f < iframes.length; ++f) {
            var iframe = iframes[f];
            if (iframe.classList.contains("non-printable")) {
                continue;
            }
            iframe.contentWindow.focus();
            iframe.contentWindow.print();
            f = iframes.length;
        }
    } else {
        window.print()
    }
}

xover.listener.on('fetch::xo:message[.!=""]', function ({ target, attribute: key }) {
    this.render()
});

xo.listener.on('xo.Source:fetch', async function ({ settings = {} }) {
    let progress = await settings.progress;
    progress && progress.remove();
})

xover.listener.on('change::@state:*', async function ({ target, attribute: key }) {
    if (event.defaultPrevented || !(target && target.parentNode)) return;
    let stylesheets = target.parentNode.stylesheets
    if (!stylesheets) return;
    let documents = stylesheets.getDocuments();
    documents = await Promise.all(documents.map(document => document.documentElement || document.fetch())).then(document => document);
    documents.filter(stylesheet => stylesheet && stylesheet.selectSingleNode(`//xsl:stylesheet/xsl:param[starts-with(@name,'state:${key}')]`)).forEach(stylesheet => stylesheet.store.render());
});

xover.listener.on('change::@xo-store', function ({ target, attribute: key }) {
    this.parentNode.section.render()
});

xover.listener.on('change::@state:busy', function ({ target, value }) {
    if (event.defaultPrevented) return;
    let store = target.store;
    if (store instanceof xover.Store && store.isActive) {
        if (value && JSON.parse(value)) {
            //targetDocument = ((document.activeElement || {}).contentDocument || document);
            //xover.sources["loading.xslt"].render({ target: , action: "append" });
            let last_stylesheet = store.stylesheets.pop();
            let document = store.document;
            document.render(document.createProcessingInstruction('xml-stylesheet', { type: 'text/xsl', href: "loading.xslt", target: last_stylesheet && last_stylesheet.target || 'body', action: "append" }));
        } else {
            let attrib = target.getAttributeNode("state:busy");
            attrib && attrib.remove();
        }
    }
});

xover.listener.on('remove::@state:busy', function ({ target, value }) {
    let store = target.store;
    if (store instanceof xover.Store && store.isActive) {
        [...document.querySelectorAll(`[xo-store="${store.tag}"][xo-stylesheet='loading.xslt']`)].removeAll();
    }
});

xover.listener.on("focusout", function (event) {
    if (event.defaultPrevented) return;
    xover.dom.lastBluredElement = event.target;

    //if (((arguments || {}).callee || {}).caller === xover.dom.clear) {
    //    xover.dom.activeElement = event.target;
    //} else {
    xover.dom.bluredElement = event.target;
    if (xover.debug["focusout"]) {
        console.log(event.target);
    }
    //}
})

var contentEdited = function (event) {
    let elem = event.srcElement;
    let source = elem && elem.scope || null
    if (source instanceof Attr) {
        if (elem.isContentEditable) {
            source.set(elem.textContent, false)
        } else {
            source.set(elem.value, false)
        }
    }
    elem.removeEventListener('blur', contentEdited);
}

xover.listener.on('input', function (event) {
    if (event.defaultPrevented) return;
    let elem = event.srcElement;
    let source = elem && elem.scope || null;
    if (source instanceof Attr) {
        if (elem.isContentEditable) {
            elem.removeEventListener('blur', contentEdited);
            elem.addEventListener('blur', contentEdited);
        }
    }
})

xover.listener.on('click', function (event) {
    if (event.defaultPrevented) return;
    var srcElement = xover.dom.findClosestElementWithAttribute(event.target, "href");
    var hashtag = (srcElement ? srcElement.getAttribute("href") : "");

    if (!hashtag.match(/^#/)) {
        return;
    }
    custom_event = new xover.listener.Event('beforeHashChange', [hashtag, (window.top || window).location.hash])
    if (hashtag !== undefined && hashtag != (window.top || window).location.hash) {
        window.top.dispatchEvent(custom_event);
    }
    if (custom_event.defaultPrevented) {
        return event.preventDefault();
    }
});

//xover.listener.on(["change", "click"], function (event) {
//    if (event.defaultPrevented) return;
//    xover.dom.bluredElement = event.target;
//    xover.delay(40).then(() => {
//        xover.dom.triggeredByTab = xover.listener.keypress.tabKey;
//    })
//})

xover.listener.on("click", function (event) {
    if (event.defaultPrevented) return;
    xover.delay(40).then(() => {
        let target_store = event.target.store;
        if (target_store) {
            if (target_store.sources.reload.interval.continue) {
                target_store.sources.reload.interval.continue();
            }
            if (xover.listener.keypress.ctrlKey && !xover.listener.keypress.shiftKey && !xover.listener.keypress.altKey/* && target_tag !== (window.top || window).location.hash)*/) {
                let target_tag = target_store.tag;
                xover.site.update({ active: target_tag, hash: target_tag });
            }
        }
    })
})

xover.listener.on(["contextmenu", "focusin"], function (event) {
    if (event.defaultPrevented) return;
    xover.delay(40).then(() => {
        let target = event.target;
        let target_store = target.store;
        if (target_store instanceof xover.Store && (event.type == 'contextmenu' || target instanceof HTMLInputElement || target instanceof HTMLSelectElement || target instanceof HTMLTextAreaElement)) {
            if (target_store.sources.reload.interval.pause) {
                target_store.sources.reload.interval.pause();
            }
        }
    })
})

var _Network_state = true;
xover.browser.updateIndicator = function () {
    if (navigator.onLine) {
        console.info("online")
        _Network_state = true;
    } else {
        console.warn("offline")
        _Network_state = false;
    }
}
xover.listener.on(["online", "offline"], xover.browser.updateIndicator);
xover.browser.updateIndicator();

xover.string = {}
xover.string.htmlDecode = function (string) {
    var txt = document.createElement("textarea");
    txt.style.textTransform = 'unset'
    txt.innerHTML = string;
    return txt.value;
}

xover.string.getFileParts = function (file_name = '') {
    let parts = {}
    parts["extension"] = file_name.lastIndexOf('.') != -1 && file_name.substring(file_name.lastIndexOf('.') + 1) || undefined;
    parts["name"] = file_name.substring(file_name.lastIndexOf('/') + 1)
    parts["path"] = file_name.substring(0, file_name.lastIndexOf('/') + 1)
    return parts;
}

xover.json.isValid = function (input) {
    try {
        return !(input instanceof Node) && input !== undefined && [{}.constructor, [].constructor].includes(JSON.parse(JSON.stringify(input)).constructor)
    } catch (e) {
        return false;
    }
    return true;
}

xover.json.tryParse = function (input) {
    let output;
    if (xover.json.isValid(input) || !input) {
        return input;
    }
    try {
        output = eval(`(${input})`);
    } catch (e) {
        output = eval(`(${JSON.stringify(input && input.value || `${input}`)})`)
    }
    return output;
}

Object.defineProperty(xover.string, 'replace', {
    value: function (input, search_text, replace_text, is_regex) {
        let result;
        if (is_regex) {
            let regex = new RegExp(search_text.replace(/([\\"])/, '\\$1'), "ig");
            result = String(input).replace(regex, replace_text)
        } else if (String(input).replaceAll) {
            result = String(input).replaceAll(search_text, replace_text)
        } else {
            let regex = new RegExp(search_text.replace(/([\[\]\(\)\\"])/, '\\$1'), "ig");
            result = String(input).replace(regex, replace_text)
        }
        return result;
    },
    writable: true, enumerable: false, configurable: false
})

xover.string.trim = function (text) {
    if (typeof (text) != "string") return text;
    return text.replace(/\s+$/, '').replace(/^\s+/, '')
}

xover.string.toTitleCase = function (str) {
    /*Code obtained from https://stackoverflow.com/questions/196972/convert-string-to-title-case-with-javascript */
    var i, j, lowers, uppers;
    if (!str) return str;
    if (xover.string.isEmail(str)) {
        return str.toLowerCase();
    } else if (xover.string.isRFC(str) || xover.string.isCURP(str)) {
        return str.toUpperCase();
    }

    str = str.replace(/([^\W_]+[^\s-]*) */g, function (txt) {
        return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
    });

    // Certain minor words should be left lowercase unless 
    // they are the first or last words in the string
    lowers = ['A', 'An', 'The', 'And', 'But', 'Or', 'For', 'Nor', 'As', 'At',
        'By', 'For', 'From', 'In', 'Into', 'Near', 'Of', 'On', 'Onto', 'To', 'With', 'A', 'De', 'Y', 'O'];
    for (let i = 0, j = lowers.length; i < j; i++)
        str = str.replace(new RegExp('\\s' + lowers[i] + '\\s', 'g'),
            function (txt) {
                return txt.toLowerCase();
            });

    // Certain words such as initialisms or acronyms should be left uppercase
    uppers = ['Id', 'Tv', 'RFC', 'CURP', 'Sa', 'Cv', 'Rl'];
    for (let i = 0, j = uppers.length; i < j; i++)
        str = str.replace(new RegExp('\\b' + uppers[i] + '\\b', 'g'),
            uppers[i].toUpperCase());

    return str;
}

xover.string.isRFC = function (str) {
    if (/^([A-Z,Ñ,&]{3,4}([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|1[0-9]|2[0-9]|3[0-1])[A-Z|\d]{3})$/.test(str)) {
        return (true)
    }
    return (false)
}

xover.string.isEmail = function (str) {
    if (/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(str)) {
        return (true)
    }
    return (false)
}

xover.string.isCURP = function (str) {
    if (/^([A-Z]{4}([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|1[0-9]|2[0-9]|3[0-1])[HM](AS|BC|BS|CC|CL|CM|CS|CH|DF|DG|GT|GR|HG|JC|MC|MN|MS|NT|NL|OC|PL|QT|QR|SP|SL|SR|TC|TS|TL|VZ|YN|ZS|NE)[A-Z]{3}[0-9A-Z]\d)$/.test(str)) {
        return (true)
    }
    return (false)
}

function isNumericOrMoney(sValue) {
    var sCurrencyPath = /^(?:\$)?(?:\-)?\d{1,3}((?:\,)\d{3})*\.?\d*$/
    return (String(sValue).search(sCurrencyPath) != -1)
}

function isFunction(a) {
    return typeof a == 'function';
}

function existsFunction(function_name) {
    try {
        return eval(`typeof ${function_name}`) === "function"
    } catch (e) {
        return false;
    }
}

function isObject(a) {
    return (a && typeof a == 'object') || isFunction(a);
}

function isEmpty(str) {
    return (!str || /^\s*$/.test(str));
}

function isNumber(value) {
    return parseFloat(value) == value
}

xover.dom.getCaretPosition = function (elem) {
    let caret_pos, caret_start, caret_end;
    elem = elem instanceof Element && elem || typeof (elem) == 'string' && document.querySelector(elem);
    if (!(elem && elem.value)) return;
    if (elem.isContentEditable || (elem.selectionStart || elem.selectionStart == 0)) {
        caret_start = elem.selectionStart;
        caret_end = elem.selectionEnd;
        caret_direction = elem.selectionDirection;
        if (caret_start == caret_end) {
            caret_pos = [caret_start];
        } else if (caret_start > caret_end || caret_direction == 'backward') {
            caret_pos = [caret_end, caret_start];
        } else {
            caret_pos = [caret_start, caret_end];
        }
    }
    else if (document.selection) {
        elem.focus();
        var selection = document.selection.createRange();
        selection.moveStart('character', -elem.value.length);
        caret_pos = selection.text.length;
    }
    return caret_pos;
}

xover.dom.setCaretPosition = function (elem, caret_pos) {
    if (elem && elem.focus) {
        if (!(elem.isContentEditable || (elem.selectionStart || elem.selectionStart == 0) || document.selection)) {
            elem.focus();
        }
        else if (typeof (elem.value) != "undefined") {
            let [start, end] = caret_pos || [];
            if (elem.createTextRange) {
                let range = elem.createTextRange();
                if (end) {
                    if (start > end) {
                        elem.setSelectionRange(end, start, "backward");
                    } else {
                        elem.setSelectionRange(start, end);
                    }
                    xover.site.activeCaret = [start, end];
                } else {
                    range.move('character', start);
                    range.select();
                    xover.site.activeCaret = [start];
                }
            }
            else if (elem.setSelectionRange) {
                elem.focus();
                if (end) {
                    if (start > end) {
                        elem.setSelectionRange(end, start, "backward");
                    } else {
                        elem.setSelectionRange(start, end);
                    }
                    xover.site.activeCaret = [start, end];
                } else {
                    elem.setSelectionRange(start, start);
                    xover.site.activeCaret = [start];
                }
            } else {
                elem.focus();
            }
        }
    }
}

xover.dom.elementVisible = function (el, container) {
    if (container.scrollTop > el.offsetTop || container.scrollLeft > el.offsetLeft) {
        return false;
    }
    return true;
}

xover.data.getScrollPosition = async function (target) {
    var coordinates = ((target || await xover.stores.active.documentElement || document.createElement('p')).selectNodes('@state:x-position|@state:y-position') || []).reduce((json, attr) => { json[attr.localName.replace('-position', '')] = attr.value; return json; }, {});
    return coordinates;
}

xover.dom.getScrollPosition = function (el) {
    var targetDocument = ((document.activeElement || {}).contentDocument || document);
    var el = (el || targetDocument.activeElement || targetDocument.querySelector('body'));//(el || window);
    scrollParent = (xover.dom.getScrollParent(el) || targetDocument.querySelector('body'));
    var coordinates =
    {
        x: (scrollParent.pageXOffset !== undefined ? scrollParent.pageXOffset : scrollParent.scrollLeft),
        y: (scrollParent.pageYOffset !== undefined ? scrollParent.pageYOffset : scrollParent.scrollTop),
        target: scrollParent.selector
    }
    return coordinates;
}


xover.dom.setScrollPosition = function (el, coordinates) {
    el = (typeof (el) == 'string' && document.querySelector(el) || el);
    if (el) {
        if (!(coordinates && el.scrollTo)) {
            return;
        }
        el.scrollTo(coordinates.x, coordinates.y);
    }/* else {
        Object.entries(xover.site.get("scrollableElements", {})).map(([selector, coordinates]) => {
            xover.dom.setScrollPosition(selector, coordinates)
        })
    }*/
}

xover.dom.getScrollParent = function (el) {
    if (el == null) {
        return null;
    }
    if (el.scrollHeight > el.clientHeight && (el.scrollTop || el.scrollLeft)) {
        return el;
    } else {
        return xover.dom.getScrollParent(el.parentNode);
    }
}

Object.defineProperty(xover.site, 'getScrollableElements', {
    value: function (scope) {
        var target = (scope || (document.activeElement || {}).contentDocument || document);
        function isScrollable(el) {
            //return el.scrollHeight >= el.clientHeight && (el.scrollTop || el.scrollLeft);
            // Check if the element has overflow and overflow-y set to auto or scroll
            if (!(el instanceof HTMLElement)) return false;
            const overflowY = window.getComputedStyle(el).overflowY;
            const overflowX = window.getComputedStyle(el).overflowX;
            return (overflowY === 'scroll' || overflowY === 'auto' ||
                overflowX === 'scroll' || overflowX === 'auto');
        }

        //xover.stores.active.selectNodes("//*[@state:x-position]").filter(node => {
        //    (node.getAttribute("state:x-position") > 0 || node.getAttribute("state:y-position") > 0)/* && document.querySelector(`#${node.getAttributeNS("http://panax.io/xover", "id")}`)*/
        //});
        return [...(scope && [scope] || []), ...target.querySelectorAll("*")].filter(scope => isScrollable(scope));
    }
})

//xover.dom.updateScrollableElements = function (el) {
//    var target = (el || (document.activeElement || {}).contentDocument || document);
//    Object.keys(xover.site.scrollableElements).filter(selector => document.querySelector(selector)).forEach(selector => xover.site.scrollableElements[selector] = xover.dom.getScrollPosition(document.querySelector(selector))); //Updates all scrollable elements in sight even if they are not longer scrollable.
//    let scrollable = xover.site.getScrollableElements(target);
//    scrollable.map(el => {
//        let coordinates = xover.dom.getScrollPosition(el);
//        path = el.selector;
//        xover.site.scrollableElements[path] = { x: coordinates.x, y: coordinates.y }
//    });
//    //xover.site.scrollableElements = xover.site.scrollableElements;
//    ////xover.stores.active.selectNodes("//*[@state:x-position]").filter(node => {
//    ////    return (node.getAttribute("state:x-position") > 0 || node.getAttribute("state:y-position") > 0)/* && document.querySelector(`#${node.getAttributeNS("http://panax.io/xover", "id")}`)*/
//    ////}).map(node => {
//    ////    xover.site.scrollableElements[node.getAttributeNS("http://panax.io/xover", "id")] = {}
//    ////    xover.site.scrollableElements[node.getAttributeNS("http://panax.io/xover", "id")]["x"] = node.getAttribute("state:x-position");
//    ////    xover.site.scrollableElements[node.getAttributeNS("http://panax.io/xover", "id")]["y"] = node.getAttribute("state:y-position");
//    ////});
//}

xover.dom.getNextElement = function (src) {
    src = (src || document.activeElement)
    context = (/*document.querySelector('main form') || */document.querySelector('main'));
    var focussableElements = 'a:not([disabled]), button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([disabled]):not([tabindex="-1"])';
    if (src) {
        var focussable = Array.prototype.filter.call(context.querySelectorAll(focussableElements),
            function (element) {
                //check for visibility while always include the current activeElement 
                return element.offsetWidth > 0 || element.offsetHeight > 0 || element === src
            });
        focussable = focussable.filter(el => el.tabIndex != -1);
        var index = focussable.indexOf(src);
        if (index > -1) {
            var nextElement = focussable[index + 1] || focussable[0];
            return nextElement;
        }
    }
}

xover.dom.getPrecedingElement = function (src) {
    src = (src || document.activeElement)
    context = (/*document.querySelector('main form') || */document.querySelector('main'));
    var focussableElements = 'a:not([disabled]), button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([disabled]):not([tabindex="-1"])';
    if (src) {
        var focussable = Array.prototype.filter.call(context.querySelectorAll(focussableElements),
            function (element) {
                //check for visibility while always include the current activeElement 
                return element.offsetWidth > 0 || element.offsetHeight > 0 || element === src
            });
        focussable = focussable.filter(el => el.tabIndex != -1);
        var index = focussable.indexOf(src);
        if (index > -1) {
            var nextElement = focussable[index - 1] || focussable[0];
            return nextElement;
        }
    }
}

xover.dom.focusNextElement = function () {
    var nextElement = xover.dom.getNextElement();
    nextElement.focus();
}

xover.debug.brokenXmlAttributes = function (node) {
    return node.selectNodes(`@*`).filter(attr => (!attr.prefix && attr.name.indexOf(':') != -1))
}

xover.modernize = function (targetWindow) {
    var targetWindow = (targetWindow || window);
    if (targetWindow.modernized) return;
    with (targetWindow) {
        function extend(sup, base) {
            var descriptor = Object.getOwnPropertyDescriptor(
                base.prototype, "constructor"
            );
            base.prototype = Object.create(sup.prototype);
            var handler = {
                construct: function (target, args) {
                    var obj = Object.create(base.prototype);
                    this.apply(target, obj, args);
                    return obj;
                },
                apply: function (target, that, args) {
                    sup.apply(that, args);
                    base.apply(that, args);
                }
            };
            var proxy = new Proxy(base, handler);
            descriptor.value = proxy;
            Object.defineProperty(base.prototype, 'constructor', descriptor);
            return proxy;
        }

        Date.prototype.addDays = function (days = 0) {
            var date = new Date(this.valueOf());
            date.setDate(date.getDate() + days);
            return date;
        }

        String.prototype.parseDate = function (input_format = "dd/mm/yyyy") {
            sDate = this.toString();
            var pattern = /\b(\d{1,2})(?:(\/)(\d{1,2})(?:\2(\d{2,4}))?)?/
            var currentDate = new Date();
            var [, day, separator, month, year] = (sDate.match(pattern) || []);
            let result = new Date(`${year}-${month}-${day}T00:00:00`);
            return result;
        }

        if (!String.prototype.matchAll) {
            String.prototype.matchAll = function (regex) {
                const text = this;
                const matches = [];
                const regexGlobal = new RegExp(regex, "g");

                let match;
                while ((match = regexGlobal.exec(text)) !== null) {
                    const capturingGroups = Array.prototype.slice.call(match, 1);
                    matches.push(capturingGroups);
                }

                return matches[Symbol.iterator]();
            };
        }

        if (!Object.hasOwnProperty('getPropertyDescriptor')) {
            Object.defineProperty(Object, 'getPropertyDescriptor', {
                value: function (source, key) {
                    return source && (Object.getOwnPropertyDescriptor(source.constructor.prototype, key) || Object.getPropertyDescriptor(Object.getPrototypeOf(source), key)) || null;
                },
                writable: false, enumerable: false, configurable: false
            });
        }

        if (!Object.prototype.hasOwnProperty('push')) {
            Object.defineProperty(Object.prototype, 'push', {
                value: function (key, value) {
                    this[key] = value;
                    return this;
                },
                writable: true, enumerable: false, configurable: false
            });
        }

        //if (!Object.prototype.hasOwnProperty('get')) {
        //    Object.defineProperty(Object.prototype, 'get', {
        //        value: function (key) {
        //            return this[key];
        //        },
        //        writable: true, enumerable: false, configurable: false
        //    });
        //}

        if (!String.prototype.hasOwnProperty('alert')) {
            Object.defineProperty(String.prototype, 'alert', {
                value: function () {
                    xover.dom.alert(this)
                },
                writable: true, enumerable: false, configurable: false
            });
        }

        if (!Object.prototype.hasOwnProperty('render')) {
            Object.defineProperty(Object.prototype, 'render', {
                value: function (...args) {
                    let source = this.message && typeof (this.message) === 'string' && new String(this.message) || this;
                    if (typeof (source.alert) === 'function') {
                        source.alert.apply(source, args)
                    } else if (source !== this && source.render) {
                        source.render.apply(source, args)
                    } else if (source instanceof Attr) {
                        source.value.render()
                    } else if (source instanceof Array && source.length) {
                        let ul = document.cloneNode().createElement("ul");
                        ul.append(...this.map(el => { let li = document.createElement("li"); li.textContent = el; return li }))
                        xover.dom.createDialog(ul)
                    }
                },
                writable: true, enumerable: false, configurable: false
            });
        }

        //if (!Object.prototype.hasOwnProperty('alert')) {
        //    Object.defineProperty(Object.prototype, 'alert', {
        //        value: function (target) {
        //            xover.dom.alert(this)
        //        },
        //        writable: true, enumerable: false, configurable: false
        //    });
        //}

        if (!Response.prototype.hasOwnProperty('render')) {
            Object.defineProperty(Response.prototype, 'render', {
                value: function (target) {
                    let source = typeof (this.json) != 'function' && this.json || this.document || !(this.body instanceof ReadableStream) && this.body || this.statusText || {};
                    source.render && source.render()
                },
                writable: true, enumerable: false, configurable: false
            });
        }

        if (!Object.prototype.hasOwnProperty('cloneObject')) {
            Object.defineProperty(Object.prototype, 'cloneObject', {
                value: function () {
                    return xover.json.merge({}, this);//JSON.parse(JSON.stringify(this));
                },
                writable: false, enumerable: false, configurable: false
            });
        }

        //if (!Object.prototype.hasOwnProperty('filter')) {
        //    Object.defineProperty(Object.prototype, 'filter', {
        //        get: function () {
        //            return function (_filter_function) {
        //                var subset = {}
        //                Object.entries(this).forEach(([key, value]) => {
        //                    if (_filter_function && _filter_function.apply && _filter_function.apply(this, [key, value])) {
        //                        subset[key] = value;
        //                    }
        //                })
        //                return subset;
        //            }
        //        }, set: function (input) {
        //            return;
        //        }, enumerable: false, configurable: false
        //    });
        //}

        if (!Object.prototype.hasOwnProperty('merge')) {
            Object.defineProperty(Object.prototype, 'merge', {
                value: function () {
                    let self = this;
                    for (let a = 0; a < arguments.length; a++) {
                        let object = arguments[a]
                        if (object && typeof (object) == 'object') {
                            for (let key in object) {
                                if (object[key] && object[key].constructor == {}.constructor) {
                                    self[key] = Object.prototype.merge.call(self[key] || {}, object[key]);
                                } else {
                                    let new_value = object[key];
                                    new_value = new_value instanceof Attr ? new_value.value : new_value;
                                    self[key] = (new_value !== undefined ? new_value : self[key]) //Sólo sobreescribe si es un valor diferente a undefined (incluyendo null);
                                }
                            }
                        }
                    }
                    return self;
                },
                writable: true, enumerable: false, configurable: false
            });
        }

        if (targetWindow.document.implementation.hasFeature("XPath", "3.0")) {
            if (typeof XMLDocument == "undefined") { XMLDocument = Document; }

            if (!Node.prototype.hasOwnProperty('resolveNS')) {
                Object.defineProperty(Node.prototype, 'resolveNS', {
                    get: function () {
                        let element = this;
                        let resolver = element instanceof Document ? element.createNSResolver(element) : element.ownerDocument.createNSResolver(element);

                        return function (prefix) {
                            let namespace = resolver.lookupNamespaceURI(prefix) || resolver.lookupNamespaceURI(prefix == '_' && '');
                            if (namespace == undefined) {
                                return null;
                            }
                            return namespace;

                        };
                    }
                });
            }

            HTMLTextAreaElement.native = {};
            HTMLTextAreaElement.native.select = HTMLTextAreaElement.prototype.select;
            Node.prototype.selectNodes = function (xpath, context) {
                if (this instanceof HTMLTextAreaElement && xpath == undefined) {
                    return HTMLTextAreaElement.native.select.apply(this)
                }
                if (this instanceof DocumentFragment) {
                    let newDoc = xover.xml.createNode("<root/>");
                    newDoc.append(...this.cloneNode(true).childNodes);
                    return newDoc.selectNodes(xpath)
                }
                context = context || this instanceof Node && this || this.document;
                //if (!xpath.match(/[^\w\d\-\_]/g)) {
                //    xpath = `*[${context.resolveNS("") !== null && `namespace-uri()='${context.resolveNS("")}' and ` || ''}name()='${xpath}']`
                //}
                let nsResolver = (function (element) {
                    let resolver = element instanceof Document ? element.createNSResolver(element) : element.ownerDocument.createNSResolver(element);

                    return function (prefix) {
                        return resolver.lookupNamespaceURI(prefix) || resolver.lookupNamespaceURI(prefix == '_' && '') || xover.spaces[prefix] || "urn:unknown";
                        let namespace = resolver.lookupNamespaceURI(prefix) || resolver.lookupNamespaceURI(prefix == '_' && '');
                        if (namespace == undefined) {
                            return xover.spaces[prefix] || "urn:unknown";
                        }
                        return namespace;
                    };
                }(context))

                let selection = new Array;
                let aItems;
                try {
                    aItems = (context.ownerDocument || context).evaluate(xpath, context, nsResolver, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
                } catch (e) {
                    if (e.message.match(/contains unresolvable namespaces/g)) {
                        ////let prefixes = xpath.match(/\w+(?=\:)/g);
                        ////prefixes = [...new Set(prefixes)];
                        ////for (let prefix of prefixes) {
                        ////    let target = (context.documentElement || context);
                        ////    original_setAttributeNS.call(target, 'http://www.w3.org/2000/xmlns/', `xmlns:${prefix}`, nsResolver(prefix));
                        ////}
                        ////try {
                        ////    aItems = (context.ownerDocument || context).evaluate(xpath, context, nsResolver, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
                        ////} catch (e) {
                        if (!xover.browser.isIOS()) {
                            xpath = xpath.replace(RegExp("(?<=::|@|\\/|\\[|^|\\()([\\w-_]+):([\\w-_]+|\\*)", "g"), ((match, prefix, name) => `*[namespace-uri()='${nsResolver(prefix)}' and local-name()="${name}"]`));
                            //console.log(xpath)
                        }
                        aItems = (context.ownerDocument || context).evaluate(xpath, context, nsResolver, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
                        //}
                    } else {
                        if (xover.session.debug) console.warning(e);
                        aItems = {};
                    }
                }
                for (let i = 0; i < aItems.snapshotLength; i++) {
                    selection[i] = aItems.snapshotItem(i);
                    if (selection[i] instanceof ProcessingInstruction) {
                        selection[i] = new xover.ProcessingInstruction(selection[i]);
                    }
                }
                return new xover.NodeSet(selection);
            }

            Node.prototype.selectSingleNode = function (xpath) {
                if (!xpath) {
                    return null;
                }
                xpath = xpath.replace(/&quot;/gi, '"');
                let namespace = this.resolveNS("");
                //if (!xpath.match(/[^\w\d\-\_]/g) && namespace) {
                //    xpath = `*[namespace-uri()='${namespace}' and name()='${xpath}']`
                //}
                let scope = this instanceof Node && this || this.document;
                let xItems = scope.selectNodes(`(${xpath})[1]`);
                if (xItems.length > 0) { return xItems[0]; }
                else { return null; }
            }
            Node.prototype.select = Node.prototype.selectNodes;
            Node.prototype.selectFirst = Node.prototype.selectSingleNode;
            HTMLTextAreaElement.prototype.select = Node.prototype.selectNodes;

            var original_select = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'select');
            Object.defineProperty(HTMLInputElement.prototype, 'select', {
                value: function (...args) {
                    if (!args.length) {
                        return original_select && original_select.value.apply(this, args);
                    } else {
                        return Node.prototype.select.apply(this, args)
                    }
                }
            })

            Element.prototype.createNode = function (node_description) {
                let node = xover.xml.createNode(node_description)
                this.append(node);
                return node;
            }

            Document.native = {};
            Document.native.find = Object.getOwnPropertyDescriptor(Document.prototype, 'find');
            Object.defineProperty(Document.prototype, 'find', {
                value: function (selector) {
                    try {
                        return this.querySelector(selector)
                    } catch (e) {
                        if (e.message.indexOf('not a valid selector') != -1) {
                            try {
                                return this.selectFirst(`//${selector}`)
                            } catch (e) {
                                return null;
                            }
                        }
                    }
                }
            })

            HTMLCollection.prototype.native = {};
            HTMLCollection.prototype.native.filter = Object.getOwnPropertyDescriptor(HTMLCollection.prototype, 'filter');
            Object.defineProperty(HTMLCollection.prototype, 'filter', {
                value: function (...args) {
                    if (typeof (args[0]) === 'string') {
                        return [...this].filter(el => el.selectSingleNode(args[0]))
                    } else if (typeof (args[0]) === 'function') {
                        return [args[0].apply(this, [this].concat([1, 2, 3].slice(1))) && this || null].filter(item => item);
                    }
                }
            })

            HTMLCollection.prototype.native.toArray = Object.getOwnPropertyDescriptor(HTMLCollection.prototype, 'toArray');
            Object.defineProperty(HTMLCollection.prototype, 'toArray', {
                value: function () {
                    return [...this];
                }
            })

            NodeList.prototype.native = {};
            NodeList.prototype.native.filter = Object.getOwnPropertyDescriptor(NodeList.prototype, 'filter');
            Object.defineProperty(NodeList.prototype, 'filter', {
                value: function (...args) {
                    if (typeof (args[0]) === 'string') {
                        return [...this].filter(el => el.selectSingleNode(args[0]))
                    } else if (typeof (args[0]) === 'function') {
                        return [args[0].apply(this, [this].concat([1, 2, 3].slice(1))) && this || null].filter(item => item);
                    }
                }
            })

            Array.prototype.native = {};
            Array.prototype.native.toArray = Object.getOwnPropertyDescriptor(Array.prototype, 'toArray');
            Object.defineProperty(Array.prototype, 'toArray', {
                value: function () {
                    return [...this];
                }
            })

            NodeList.prototype.native.toArray = Object.getOwnPropertyDescriptor(NodeList.prototype, 'toArray');
            Object.defineProperty(NodeList.prototype, 'toArray', {
                value: function () {
                    return [...this];
                }
            })

            NamedNodeMap.prototype.native = {};
            NamedNodeMap.prototype.native.toArray = Object.getOwnPropertyDescriptor(NamedNodeMap.prototype, 'toArray');
            Object.defineProperty(NamedNodeMap.prototype, 'toArray', {
                value: function () {
                    return [...this];
                }
            })

            Node.prototype.filter = function (...args) {
                if (typeof (args[0]) === 'string') {
                    if (this.selectSingleNode(args[0])) {
                        return [this]
                    } else {
                        return [];
                    }
                } else if (typeof (args[0]) === 'function') {
                    return [args[0].apply(this, [this].concat([1, 2, 3].slice(1))) && this || null].filter(item => item);
                }
            }

            var original_response_matches = Object.getOwnPropertyDescriptor(Response.prototype, 'matches');
            Object.defineProperty(Response.prototype, 'matches', {
                value: function (...args) {
                    let predicate = args.pop();
                    let tag = this.tag || event && event.detail && event.detail.tag || '';
                    if (predicate[0] == '#') {
                        if (tag == predicate || predicate == tag.split(/[:\?~]/)[0]) {
                            return true;
                        }
                        return false;
                    }
                    let node = this.documentElement;
                    return node && [node.ownerDocument].find(el => el && el.selectNodes(predicate).includes(node))
                }
            })

            var original_element_matches = Object.getOwnPropertyDescriptor(Element.prototype, 'matches');
            Object.defineProperty(Element.prototype, 'matches', {
                value: function (...args) {
                    let node = this;
                    try {
                        return original_element_matches && original_element_matches.value.apply(node, args);
                    } catch (e) {
                        if (e.message.indexOf('not a valid selector') != -1) {
                            /*node = node.parentNode || node.formerParentNode;*/
                            let key = args[0];
                            let remove;
                            let store = this.ownerDocument.store;
                            if (!this.parentElement && this.formerParentNode && !(this.formerParentNode instanceof Document)) {
                                store && store.observer.disconnect();
                                original_insertBefore.apply(this.formerParentNode, [this, this.formerNextSibling]);
                                remove = true;
                            }
                            let return_value = !![node.selectNodes('self::*|ancestor::*').reverse(), node.ownerDocument].flat().find(el => {
                                try {
                                    return el && el.selectNodes(el instanceof Document && key.replace(/^self::/, '') || key).includes(this)
                                } catch (e) {
                                    console.warn(`No a valid xpath was provided: ${key}`)
                                }
                            });
                            if (remove) this.remove({ silent: true });
                            store && store.observer.connect();
                            return return_value;
                        }
                    }
                }
            })

            var original_document_matches = Object.getOwnPropertyDescriptor(Document.prototype, 'matches');
            Object.defineProperty(Document.prototype, 'matches', {
                value: function (...args) {
                    let predicate = args.pop();
                    let tag = this.tag || event && event.detail && event.detail.tag || '';
                    if (predicate[0] == '#') {
                        if (tag == predicate || predicate == tag.split(/[:\?~]/)[0]) {
                            return true;
                        }
                        return false;
                    }
                    let node = this.documentElement;
                    return !!(node && [node.ownerDocument].find(el => el && el.selectNodes(predicate).includes(node)))
                }
            })

            var original_attr_matches = Object.getOwnPropertyDescriptor(Attr.prototype, 'matches');
            Object.defineProperty(Attr.prototype, 'matches', {
                value: function (...args) {
                    let node = this;
                    try {
                        if (!(original_attr_matches && node.ownerElement instanceof HTMLElement)) {
                            throw new DOMException('not a valid selector');
                        }
                        return (original_attr_matches || {}).value && original_attr_matches.value.apply(node, args);
                    } catch (e) {
                        if (e.message.indexOf('not a valid selector') != -1) {
                            node = node.parentNode || node.formerParentNode;
                            let key = args[0];
                            let remove;
                            let store = this.ownerDocument.store;
                            let reconnect = !this.disconnected
                            this.disconnect();
                            if (!this.ownerElement) {
                                store && store.observer.disconnect();
                                this.parentNode.setAttributeNode(this);
                                remove = true;
                            }
                            let return_value = !![this, node.selectNodes('self::*|ancestor::*').reverse(), node.ownerDocument].flat().find(el => el && el.selectNodes(key).includes(this));
                            if (remove) this.remove({ silent: true });
                            store && store.observer.connect();
                            reconnect && this.connect();
                            return return_value;
                        }
                    }
                }
            })

            var original_element_closest = Object.getOwnPropertyDescriptor(Element.prototype, 'closest');
            Object.defineProperty(Element.prototype, 'closest', {
                value: function (...args) {
                    let node = this;
                    try {
                        return original_element_closest && original_element_closest.value.apply(node, args);
                    } catch (e) {
                        if (e.message.indexOf('not a valid selector') != -1) {
                            node = node.parentNode || node.formerParentNode;
                            let key = args[0];
                            try {
                                let return_value = this.selectFirst(`ancestor::${key}[1]`);
                                return return_value;
                            } catch (err) {
                                return undefined;
                            }
                        }
                    }
                }
            })

            var original_attr_closest = Object.getOwnPropertyDescriptor(Attr.prototype, 'closest');
            Object.defineProperty(Attr.prototype, 'closest', {
                value: function (...args) {
                    let node = this;
                    try {
                        if (!(original_attr_closest && node.ownerElement instanceof HTMLElement)) {
                            throw new DOMException('not a valid selector');
                        }
                        return (original_attr_closest || {}).value && original_attr_closest.value.apply(node, args) || (original_element_closest || {}).value && original_element_closest.value.apply(node.parentNode, args);
                    } catch (e) {
                        if (e.message.indexOf('not a valid selector') != -1) {
                            node = node.parentNode || node.formerParentNode;
                            let key = args[0];
                            try {
                                let return_value = this.matches(key) || this.ownerElement && this.ownerElement.selectFirst(`ancestor-or-self::${key}[1]`);
                                return return_value;
                            } catch (err) {
                                return undefined;
                            }
                        }
                    }
                }
            })

            var original_StopPropagation = Object.getOwnPropertyDescriptor(Event.prototype, 'stopPropagation');
            Object.defineProperty(Event.prototype, 'stopPropagation', {
                value: function () {
                    Object.defineProperty(this, 'propagationStopped', { value: true })
                    original_StopPropagation.value.call(this);
                }
            });

            Object.defineProperty(Attr.prototype, 'dispatch', {
                value: function (event_name, ...args) {
                    let detail = { target: this, element: this.parentNode, attribute: this };
                    args.forEach(arg => {
                        if (arg instanceof Array) {
                            detail.args = detail.args || []
                            detail.args.concat(arg)
                        } else if (arg && arg.constructor === {}.constructor) {
                            detail.assign(arg)
                        } else {
                            detail.args = detail.args || []
                            detail.args.push(arg)
                        }
                    });
                    let event = new xover.listener.Event(event_name, detail, this);
                    window.top.dispatchEvent(event);
                    return event.detail.returnValue;
                }
            })

            Object.defineProperty(Element.prototype, 'dispatch', {
                value: function (event_name, ...args) {
                    let detail = { target: this, element: this };
                    args.forEach(arg => {
                        if (arg instanceof Array) {
                            detail.args = detail.args || []
                            detail.args.concat(arg)
                        } else if (arg.constructor === {}.constructor) {
                            detail.assign(arg)
                        } else {
                            detail.args = detail.args || []
                            detail.args.push(arg)
                        }
                    });
                    let event = new xover.listener.Event(event_name, detail, this);
                    window.top.dispatchEvent(event);
                    return event.detail.returnValue;
                }
            })

            Object.defineProperty(Text.prototype, 'matches', {
                value: function (...args) {
                    let node = this.parentNode;
                    let xpath = args[0];
                    try {
                        let return_value = !![this, node.selectNodes('self::*|ancestor::*').reverse(), node.ownerDocument].flat().find(el => el && el.selectNodes(xpath).includes(this));
                        return return_value;
                    } catch (e) {
                        return false;
                    }
                }
            })

            Object.defineProperty(Comment.prototype, 'matches', {
                value: function (...args) {
                    return false;
                }
            })

            Object.defineProperty(ProcessingInstruction.prototype, 'matches', {
                value: function (...args) {
                    return false;
                }
            })

            XMLDocument.prototype.compareTo = function (document, stop_at_first_change) {
                let xsl_compare = this.transform(xover.xml.createDocument(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:c="http://panax.io/xml/compare" version="1.0" id="panax_xml_compare_xsl"><xsl:output method="xml"></xsl:output><xsl:strip-space elements="*"></xsl:strip-space><xsl:variable name="smallcase" select="'abcdefghijklmnopqrstuvwxyz'"></xsl:variable><xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'"></xsl:variable><xsl:template match="/"><xsl:element name="xsl:stylesheet"><xsl:copy-of select="//namespace::*"/><xsl:attribute name="version">1.0</xsl:attribute><xsl:element name="xsl:template"><xsl:attribute name="match">/</xsl:attribute><xsl:element name="results"><xsl:element name="xsl:apply-templates"></xsl:element></xsl:element></xsl:element><xsl:element name="xsl:template"><xsl:attribute name="match">*</xsl:attribute><xsl:element name="change" namespace="http://panax.io/xml/compare"><xsl:attribute name="c:position"><xsl:value-of select="'{count(preceding-sibling::*)+1}'"></xsl:value-of></xsl:attribute><xsl:attribute name="c:namespace"><xsl:value-of select="'{namespace-uri()}'"></xsl:value-of></xsl:attribute><xsl:attribute name="c:name"><xsl:value-of select="'{name()}'"></xsl:value-of></xsl:attribute><xsl:attribute name="c:type"><xsl:text>Node</xsl:text></xsl:attribute><xsl:element name="xsl:copy-of"><xsl:attribute name="select">@*</xsl:attribute></xsl:element><xsl:element name="xsl:apply-templates"></xsl:element></xsl:element></xsl:element><xsl:element name="xsl:template"><xsl:attribute name="match">text()</xsl:attribute><xsl:element name="change" namespace="http://panax.io/xml/compare"><xsl:attribute name="c:type"><xsl:text>Text</xsl:text></xsl:attribute><xsl:attribute name="c:position"><xsl:value-of select="'{count(preceding-sibling::*)}'"></xsl:value-of></xsl:attribute><xsl:attribute name="c:text"><xsl:value-of select="'{.}'"></xsl:value-of></xsl:attribute></xsl:element></xsl:element><xsl:apply-templates></xsl:apply-templates></xsl:element></xsl:template><xsl:template name="escape-xml"><xsl:param name="wrapper">&quot;</xsl:param><xsl:param name="text"></xsl:param><xsl:if test="$text != ''"><xsl:variable name="head" select="substring($text, 1, 1)"></xsl:variable><xsl:variable name="tail" select="substring($text, 2)"></xsl:variable><xsl:choose><xsl:when test="$head = '&amp;'">&amp;amp;</xsl:when><xsl:when test="$head = '&lt;'">&amp;lt;</xsl:when><xsl:when test="$head = '&gt;'">&amp;gt;</xsl:when><xsl:when test="$head = '&quot;'">&amp;quot;</xsl:when><xsl:when test="$wrapper=&quot;'&quot; and $head = &quot;'&quot;">&amp;apos;</xsl:when><xsl:otherwise><xsl:value-of select="$head"></xsl:value-of></xsl:otherwise></xsl:choose><xsl:call-template name="escape-xml"><xsl:with-param name="text" select="$tail"></xsl:with-param></xsl:call-template></xsl:if></xsl:template><xsl:template name="escape-quot"><xsl:param name="string"></xsl:param><xsl:variable name="quot">&quot;</xsl:variable><xsl:variable name="escaped-quot">&amp;quot;</xsl:variable><xsl:text>&quot;</xsl:text><xsl:choose><xsl:when test="contains($string, $quot)"><xsl:value-of select="substring-before($string, $quot)"></xsl:value-of><xsl:text>&quot;,'&quot;',</xsl:text><xsl:call-template name="escape-quot"><xsl:with-param name="string" select="substring-after($string, $quot)"></xsl:with-param></xsl:call-template><xsl:text>,&quot;</xsl:text></xsl:when><xsl:otherwise><xsl:value-of select="$string"></xsl:value-of></xsl:otherwise></xsl:choose><xsl:text>&quot;</xsl:text></xsl:template><xsl:template name="escape-apos"><xsl:param name="string"></xsl:param><xsl:choose><xsl:when test="contains($string, &quot;'&quot;)"><xsl:value-of select="substring-before($string, &quot;'&quot;)"></xsl:value-of><xsl:text>'</xsl:text><xsl:call-template name="escape-apos"><xsl:with-param name="string" select="substring-after($string, &quot;'&quot;)"></xsl:with-param></xsl:call-template></xsl:when><xsl:otherwise><xsl:value-of select="$string"></xsl:value-of></xsl:otherwise></xsl:choose></xsl:template><xsl:template match="*|text()"><xsl:apply-templates></xsl:apply-templates><xsl:element name="xsl:template"><xsl:attribute name="match"><xsl:apply-templates select="." mode="path"></xsl:apply-templates></xsl:attribute><xsl:element name="ok" namespace="http://panax.io/xml/compare"><xsl:attribute name="c:position"><xsl:value-of select="'{count(preceding-sibling::*)+1}'"></xsl:value-of></xsl:attribute><xsl:attribute name="c:name"><xsl:value-of select="'{name()}'"></xsl:value-of></xsl:attribute><xsl:copy-of select="@*"></xsl:copy-of><xsl:element name="xsl:apply-templates"></xsl:element></xsl:element></xsl:element></xsl:template><xsl:template match="*" mode="simple-path"><xsl:param name="position"><xsl:value-of select="count(preceding-sibling::*)+1"></xsl:value-of></xsl:param><xsl:apply-templates select="ancestor::*[1]" mode="simple-path"></xsl:apply-templates><xsl:text>/*</xsl:text><xsl:text>[</xsl:text><xsl:value-of select="$position"></xsl:value-of><xsl:text>]</xsl:text></xsl:template><xsl:template match="*" mode="path"><xsl:param name="position"><xsl:value-of select="count(preceding-sibling::*)+1"></xsl:value-of></xsl:param><xsl:apply-templates select="ancestor::*[1]" mode="simple-path"></xsl:apply-templates><xsl:text>/*</xsl:text><xsl:text>[</xsl:text><xsl:value-of select="$position"></xsl:value-of><xsl:text>]</xsl:text><xsl:text>[local-name()='</xsl:text><xsl:value-of select="local-name()"></xsl:value-of><xsl:text>']</xsl:text><xsl:text>[namespace-uri()='</xsl:text><xsl:value-of select="namespace-uri()"></xsl:value-of><xsl:text>']</xsl:text><xsl:text>[1=1 </xsl:text><xsl:for-each select="@*"><xsl:variable name="value"><xsl:text>concat('',</xsl:text><xsl:call-template name="escape-quot"><xsl:with-param name="string"><xsl:value-of select="." disable-output-escaping="yes"></xsl:value-of></xsl:with-param></xsl:call-template><xsl:text>)</xsl:text></xsl:variable><xsl:value-of select="concat(' and @',name(.),'=',$value)"></xsl:value-of></xsl:for-each><xsl:text>]</xsl:text></xsl:template><xsl:template match="text()" mode="path"><xsl:param name="position"><xsl:value-of select="count(preceding-sibling::*)+1"></xsl:value-of></xsl:param><xsl:apply-templates select="ancestor::*[1]" mode="simple-path"></xsl:apply-templates><xsl:text>/text()</xsl:text><xsl:text>[</xsl:text><xsl:value-of select="$position"></xsl:value-of><xsl:text>]</xsl:text><xsl:variable name="unescaped-value"><xsl:value-of select="." disable-output-escaping="yes"></xsl:value-of></xsl:variable><xsl:variable name="value"><xsl:text>concat('',</xsl:text><xsl:call-template name="escape-quot"><xsl:with-param name="string"><xsl:value-of select="." disable-output-escaping="yes"></xsl:value-of></xsl:with-param></xsl:call-template><xsl:text>)</xsl:text></xsl:variable><xsl:value-of select="concat(&quot;[.=&quot;,$value,&quot;]&quot;)"></xsl:value-of></xsl:template></xsl:stylesheet>`));
                if (stop_at_first_change) {
                    xsl_compare.selectSingleNode('//c:change/xsl:apply-templates').remove();
                }

                let details = document.transform(xsl_compare)
                return details;
            }

            if (!Node.prototype.hasOwnProperty('$')) {
                Object.defineProperty(Node.prototype, '$', {
                    enumerable: true,
                    get: function () {
                        let node = this;
                        let handler = {
                            get: function (target, prop) {
                                let new_proxy;
                                if (target === Node.prototype.selectSingleNode) {
                                    new_proxy = target.apply(node, [prop]);
                                    new_proxy = (new_proxy && new_proxy.selectSingleNode("xson:object|xson:array") || new_proxy);
                                } else if (target[prop] && isFunction(target[prop])) {
                                    return (function () {
                                        return target[prop].apply(target, arguments);
                                    });
                                } else if (typeof (prop) == 'symbol') {
                                    return target[prop];
                                } else if (target instanceof Node) {
                                    if (target.selectSingleNode("self::xson:object")) {
                                        new_proxy = target.selectSingleNode(prop);
                                        new_proxy = (new_proxy.selectSingleNode("xson:object|xson:array") || new_proxy);
                                    } else if (Number.parseInt(prop) == prop && target.selectSingleNode("self::xson:array")) {
                                        new_proxy = target.selectSingleNode("self::xson:array").selectNodes("*")[prop]
                                    } else if (Number.parseInt(prop) == prop && target.selectSingleNode("xson:array")) {
                                        new_proxy = target.selectSingleNode("xson:array").selectNodes("*")[prop]
                                    } else if (target.selectSingleNode("self::*[not(*[2])]/*[self::xson:object or self::xson:array]")) {
                                        new_proxy = target.selectSingleNode("*").selectSingleNode(prop);
                                    } else {
                                        new_proxy = target.selectNodes(prop);
                                        if (!new_proxy.length) {
                                            new_proxy = null;
                                        }
                                    }
                                    //}
                                    //if (target.constructor == [].constructor) {
                                    //    if (target.selectSingleNode("self::xson:object")) {
                                    //        return new Proxy(new_proxy.length > 1 || target.getAttribute && target.getAttribute("xsi:type") == 'array' || target.parentNode && target.parentNode.name == 'xson:array' ? new_proxy : new_proxy[0], handler);
                                    //    }
                                } else if (prop in target) {
                                    new_proxy = target[prop];
                                }
                                if (new_proxy) {
                                    return new Proxy(new_proxy, handler);
                                } else if (target instanceof Node && prop === 'node') {
                                    return target;
                                }
                                new_proxy = target.constructor == [].constructor && target.find(el => el.nodeName == prop) || target;
                                if (new_proxy.length) {
                                    return new Proxy(new_proxy.length > 1 || target.getAttribute && target.getAttribute("xsi:type") == 'array' || target.parentNode && target.parentNode.name == 'xson:array' ? new_proxy : new_proxy[0], handler);
                                } else {
                                    return null;
                                }
                            }
                            , set: function (target, prop, value) {
                                return target[prop] = value;
                            }
                        }
                        return new Proxy(this.selectSingleNode, handler);
                        //return new Proxy(this.documentElement && this.selectSingleNode("xson:object|xson:array") || this, handler);
                    }
                });
            }

            if (!Node.prototype.hasOwnProperty('$$')) {
                Object.defineProperty(Node.prototype, '$$', {
                    enumerable: true,
                    get: function () {
                        return this.selectNodes;
                    }
                });
            }

            if (!Node.prototype.hasOwnProperty('highlight')) {
                Object.defineProperty(Node.prototype, 'highlight', {
                    value: function () {
                        let node = this;
                        if (node.nodeType !== 2) {
                            [node instanceof HTMLElement && node || undefined, ...document.querySelectorAll(`#${node.getAttributeNS("http://panax.io/xover", "id")},[xo-store="${node.getAttributeNS("http://panax.io/xover", "id")}"]`)].filter(el => el).map(target => target.style.outline = '#f00 solid 2px');
                        }
                    },
                    writable: false, enumerable: false, configurable: false
                });
            }

            if (!Node.prototype.hasOwnProperty('selector')) {
                Object.defineProperty(Node.prototype, 'selector', {
                    enumerable: true,
                    get: function () {
                        if (!(this.ownerDocument instanceof HTMLDocument)) {
                            return null;
                        }
                        let selector_type = this.preferredSelectorType || this.event instanceof Event && 'full_path' || 'fast';
                        let buildQuerySelector = function (target, path = []) {
                            if (!(target && target.parentNode)) {
                                return path.filter(el => el).join(" > ");
                            } else if (target.id) {
                                path.unshift(`${target.tagName}[id='${target.id}']`);
                            } else if ((target.classList || []).length && selector_type != 'full_path') {
                                let classes = [...target.classList].filter(class_name => !class_name.match("[.]"));
                                path.unshift(target.tagName + (classes.length && '.' + classes.join(".") || ""));
                            } else if (target.nodeName == '#text') {
                                path.unshift(buildQuerySelector(target.parentNode, path.flat()));
                            } else {
                                path.unshift(target.tagName || '*');
                            }
                            if (target instanceof Element && target.hasAttribute("xo-stylesheet")) {
                                path[0] = path[0] + `[xo-stylesheet='${target.getAttribute("xo-stylesheet")}']`;
                            }
                            if (target instanceof Element && target.hasAttribute("xo-store")) {
                                path[0] = path[0] + `[xo-store='${target.getAttribute("xo-store")}']`;
                            }

                            if (target.ownerDocument.querySelector(path.filter(el => el).join(" > ")) === target) {
                                return path.filter(el => el).join(" > ");
                            } else if (target.parentNode && target.parentNode.querySelector(path.filter(el => el).join(" > "))) {
                                let position = target.parentNode && [...target.parentNode.children].findIndex(el => el == target);
                                if (position) {
                                    path[path.length - 1] = `${path[path.length - 1]}:nth-child(${position + 1})`;
                                }
                                path.unshift(buildQuerySelector(target.parentNode, []));
                            } else {
                                return path.filter(el => el).join(" > ");
                            }
                            return path.filter(el => el).flat().join(" > ");
                        }

                        return buildQuerySelector(this);
                    }

                });
            }

            var original_createProcessingInstruction = XMLDocument.prototype.createProcessingInstruction;
            XMLDocument.prototype.createProcessingInstruction = function (target, data) {
                if (target) {
                    let last_stylesheet = this.selectNodes("processing-instruction('xml-stylesheet')").pop();
                    let definition = data.constructor === {}.constructor && xover.json.toAttributes(data) || data instanceof ProcessingInstruction && data.textContent || data
                    let piNode = new xover.ProcessingInstruction(original_createProcessingInstruction.call(this, 'xml-stylesheet', definition));
                    return piNode;
                }
            }

            XMLDocument.prototype.consolidate = function (xsl) {
                xsl = this.cloneNode(true);
                var imports = xsl.documentElement.selectNodes("xsl:import|xsl:include");
                var processed = {};
                while (imports.length) {
                    imports.map(node => {
                        let href = node.getAttribute("href");
                        if (xsl.selectSingleNode(`//comment()[contains(.,'=== Imported from "${href}" ===')]`)) {
                            node.remove();
                        } else if (xover.sources[href]) {
                            //xsltProcessor.importStylesheet(xover.sources[href]);
                            let fragment = document.createDocumentFragment();
                            fragment.append(xsl.createComment(` === Imported from "${href}" ===>>>>>>>>>>>>>>> `));
                            let sources = xover.sources[href].cloneNode(true);
                            Object.entries(xover.json.difference(xover.xml.getNamespaces(sources), xover.xml.getNamespaces(xsl))).map(([prefix, namespace]) => {
                                xsl.documentElement.setAttributeNS('http://www.w3.org/2000/xmlns/', `xmlns:${prefix}`, namespace)
                            });
                            fragment.append(...sources.documentElement.childNodes);
                            fragment.append(xsl.createComment(` <<<<<<<<<<<<<<<=== Imported from "${href}" === `));

                            replaceChild_original.apply(node.parentNode, [fragment, node]); //node.replace(fragment);
                            xsl.documentElement.selectNodes(`xsl:import[@href="${href}"]|xsl:include[@href="${href}"]`).remove(); //Si en algún caso hay más de un nodo con el mismo href, quitamos los que quedaron (sino es posible que no se quite)
                        } else {
                            console.warn(`Import "${href}" not available.`)
                        }
                        processed[href] = true;
                        //}
                    });
                    var xsltProcessor = new XSLTProcessor();
                    xsltProcessor.importStylesheet(xover.xml.createDocument(`
            <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                <xsl:output method="xml" indent="no" omit-xml-declaration="yes"/>
                <xsl:key name="node_by_name" use="concat(name(),'::',@name)" match="/*/xsl:param"/>
                <xsl:key name="node_by_name" use="concat(name(),'::',@name)" match="/*/xsl:variable"/>
                <xsl:key name="node_by_name" use="concat(name(),'::',@name)" match="/*/xsl:template[@name]"/>
                <xsl:key name="node_by_name" use="concat(name(),'::',@href)" match="/*/xsl:include"/>
                <xsl:key name="node_by_name" use="concat(name(),'::',@href)" match="/*/xsl:import"/>
                <xsl:key name="node_by_name" use="concat(name(),'::')" match="/*/xsl:output"/>
                <xsl:template match="@* | * | text() | processing-instruction() | comment()" priority="-1">
                    <xsl:if test="count(key('node_by_name',concat(name(),'::',@name,@href))[last()]|.)&lt;=1">
                        <xsl:copy-of select="."/>
                    </xsl:if>
                </xsl:template>
                <xsl:template match="/*">                                
                <xsl:copy>
                    <xsl:copy-of select="@*"/>
                    <xsl:apply-templates/>
                </xsl:copy>
                </xsl:template>
            </xsl:stylesheet>
        `), 'text/xml');
                    xsl = xsltProcessor.transformToDocument(xsl);
                    xsl.source = this.source;
                    xsl.store = this.store;
                    xsl.href = this.href;
                    xsl.url = this.url;
                    imports = xsl.documentElement.selectNodes("xsl:import|xsl:include").filter(node => {
                        return !(processed[node.getAttribute("href")]) || xsl.selectSingleNode(`//comment()[contains(.,'=== Imported from "${node.getAttribute("href")}" ===')]`);
                    });
                }
                return xsl;
            }

            XMLDocument.prototype.toClipboard = function () {
                let source = this;
                var dummyContent = source.toString();
                var dummy = (document.createElement('input'));
                dummy.style.textTransform = 'unset'
                dummy.value = dummyContent;
                document.body.appendChild(dummy);
                dummy.select();
                document.execCommand('copy');
                dummy.remove();
                return;
            }

            XMLDocument.prototype.findById = function (xo_id) {
                return this.selectSingleNode('//*[@xo:id="' + xo_id + '"]')
            }

            Object.defineProperty(XMLDocument.prototype, `fetch`, {
                get: function () {
                    let self = this;
                    return async function (...args) {
                        let context = this;
                        if (!self.hasOwnProperty("source")) {
                            return Promise.reject("Document is not associated to a Source and can't be fetched");
                        }
                        let __document = self;
                        let store = self.store;
                        context.fetching = context.fetching || new Promise((resolve, reject) => {
                            self.source && self.source.fetch.apply(context, args).then(new_document => {
                                if (!(new_document instanceof Document)) {
                                    Promise.reject(new_document);
                                }
                                window.top.dispatchEvent(new xover.listener.Event(`fetch`, { document: new_document, store: store, old: __document }, new_document));
                                __document.href = new_document.href;
                                __document.url = new_document.url;
                                __document.replaceBy(new_document); //transfers all contents
                                resolve(__document);
                            }).catch(async (e) => {
                                if (!e) {
                                    return reject(e);
                                }
                                let document = e.document;
                                let targets = []
                                if (e.status != 404 && document && document.render) {
                                    targets = await document.render();
                                    if (!(targets && targets.length)) {
                                        return reject(e)
                                    }
                                } else {
                                    return reject(e);
                                }
                            }).finally(() => {
                                context.fetching = undefined;
                            });
                        }).catch(async (e) => {
                            return Promise.reject(e);
                        });
                        return context.fetching;
                    }
                }
            })


            //XMLDocument.prototype.initialize = async function () {
            //    if (this instanceof XMLDocument) {
            //        xover.manifest.getSettings(this, 'stylesheets').reverse().forEach(stylesheet => this.addStylesheet(stylesheet));
            //    }
            //    this.stylesheets.filter(stylesheet => stylesheet.role == 'init' && !this.selectSingleNode(`comment()[.="Initialized by ${stylesheet.href}"]`)).forEach(async stylesheet => {
            //        let _document_stylesheet = stylesheet.document;
            //        _document_stylesheet = await _document_stylesheet.fetch()
            //        if (_document_stylesheet) {
            //            _document_stylesheet.append(this.createComment('Initialized by ' + stylesheet.href));
            //        }

            //        let new_document = this.transform(_document_stylesheet);
            //        if ((((new_document.documentElement || {}).namespaceURI || '').indexOf("http://www.w3.org") == -1)) {
            //            this.document.replaceBy(new_document);
            //        } else {
            //            //delete stylesheet["role"];
            //            //__document.addStylesheet(stylesheet);
            //            console.warn("Initial transformation shouldn't yield a html or any other document from the w3 standard.");
            //        }
            //    });
            //}

            XMLDocument.prototype.reload = async function () {
                await this.fetch()
                let store = this.store;
                [...top.document.querySelectorAll(`[xo-stylesheet="${this.href}"]`)].filter(el => el.store === store).forEach((el) => el.render())
            }

            if (!XMLDocument.prototype.hasOwnProperty('type')) {
                Object.defineProperty(XMLDocument.prototype, 'type', {
                    get: function () {
                        let self = this;
                        return (Object.entries(xover.spaces).find(([key, namespace]) => self.documentElement && namespace == self.documentElement.namespaceURI) || [])[0] || (this.documentElement || {}).prefix || "xml";
                    }
                })
            }

            XMLDocument.prototype.getNamespaces = function () {
                return this.documentElement && this.documentElement.getNamespaces() || {};
            }

            HTMLDocument.prototype.getNamespaces = function () {
                return this.documentElement && this.documentElement.getNamespaces() || {};
            }

            Object.defineProperty(XMLDocument.prototype, 'stylesheets',
                {
                    get: function () {
                        let self = this;
                        let stylesheets_nodes = this.selectNodes("processing-instruction('xml-stylesheet')");
                        Object.defineProperty(stylesheets_nodes, 'getDocuments', {
                            value: function () {
                                let docs = []
                                for (let stylesheet of this) {
                                    docs.push(stylesheet.document);
                                }
                                return docs;
                            },
                            writable: false, enumerable: false, configurable: false
                        });

                        Object.defineProperty(stylesheets_nodes, 'toJSON', {
                            value: function () {
                                let json = []
                                for (let stylesheet of this) {
                                    json[stylesheet.href] = stylesheet
                                }
                                return json;
                            },
                            writable: false, enumerable: false, configurable: false
                        });

                        return new Proxy(stylesheets_nodes, {
                            get: function (target, prop) { //para búsquedas por href
                                if (prop in target) {
                                    return target[prop];
                                }
                                return target.find(stylesheet => stylesheet.href == prop);
                            }
                        })
                        return stylesheets_nodes
                    }
                }
            );

            Object.defineProperty(Node.prototype, 'getStylesheets', {
                value: function (predicate) {
                    var document = (this.document || this.ownerDocument || this);
                    if (this instanceof xover.Store) {
                        document.store = this
                    }
                    if (predicate && predicate.constructor === {}.constructor) {
                        predicate = Object.entries(predicate).reduce((result, [key, value]) => { result += `[contains(.,'${key}="${value}"')]`; return result }, '')
                    } else {
                        predicate = (predicate ? `[${predicate}]` : '');
                    }
                    stylesheets_nodes = document.selectNodes("//processing-instruction('xml-stylesheet')" + predicate);
                    //_stylesheets = [];
                    //for (let s = 0; s < stylesheets_nodes.length; ++s) {
                    //    let stylesheet = xover.json.fromAttributes(stylesheets_nodes[s].textContent);
                    //    Object.defineProperty(stylesheet, 'ownerDocument', {
                    //        value: document
                    //    });
                    //    Object.defineProperty(stylesheet, 'document', {
                    //        get: function () {
                    //            return ((this.ownerDocument.store || {}).sources || {})[this.href] || xover.sources[this.href]
                    //        }
                    //    });

                    //    _stylesheets.push(stylesheet);
                    //}
                    //Object.defineProperty(_stylesheets, 'ownerDocument', {
                    //    get: function () {
                    //        return document;
                    //    }
                    //});
                    //Object.defineProperty(_stylesheets, 'remove', {
                    //    value: function () {
                    //        for (let stylesheet of this) {
                    //            var target = this.ownerDocument.getStylesheet({ href: stylesheet.href });
                    //            if (target) target.remove();
                    //        }
                    //        //xover.dom.refresh();
                    //    },
                    //    writable: false, enumerable: false, configurable: false
                    //});
                    Object.defineProperty(stylesheets_nodes, 'getDocuments', {
                        value: function () {
                            let docs = []
                            for (let stylesheet of this) {
                                docs.push(this.document);
                                //docs.push(this.ownerDocument.store.sources[stylesheet.href] || xover.sources[stylesheet.href])
                            }
                            return Promise.all(docs);
                        },
                        writable: false, enumerable: false, configurable: false
                    });
                    return stylesheets_nodes;
                }
            })

            XMLDocument.prototype.getStylesheet = function (predicate) {
                let document = (this.document || this);

                if (predicate && predicate.constructor === {}.constructor) {
                    predicate = Object.entries(predicate).reduce((result, [key, value]) => { result += `[contains(.,'${key}="${value}"')]`; return result }, '')
                } else {
                    predicate = (predicate ? `[contains(.,'href="${predicate}"')]` : '');
                }
                return document.selectSingleNode(`//processing-instruction('xml-stylesheet')${predicate}`);
            }

            XMLDocument.prototype.addStylesheet = function (definition, target, refresh) {
                let store = this.store;
                let style_definition;
                let document = (this.document || this);
                if (definition.constructor === {}.constructor) {
                    definition = xover.json.merge({ type: 'text/xsl' }, definition);
                    style_definition = xover.json.toAttributes(definition);
                } else {
                    style_definition = definition
                }
                let stylesheet = this.getStylesheet(definition.href);
                if (!stylesheet) {
                    stylesheet = document.createProcessingInstruction('xml-stylesheet', style_definition);
                    if (store && (refresh/* || !store.state.initializing*/)) {
                        store.render();
                    }
                    let beforeEvent = new xover.listener.Event('beforeAddStylesheet', { stylesheet: stylesheet }, this);
                    window.top.dispatchEvent(beforeEvent);
                    if (beforeEvent.cancelBubble || beforeEvent.defaultPrevented) return;
                    document.insertBefore(stylesheet, target || document.selectSingleNode(`(processing-instruction('xml-stylesheet')${definition.role == 'init' ? '' : definition.role == 'binding' ? `[not(contains(.,'role="init"') or contains(.,'role="binding"'))]` : '[1=0]'} | *[1])[1]`));
                }
                return stylesheet; //.document.documentElement && document || stylesheet.document.fetch();
            }

            XMLDocument.prototype.removeStylesheet = function (definition_or_stylesheet) {
                let style_definition, pi;
                let document = this;
                if (definition_or_stylesheet instanceof ProcessingInstruction) {
                    pi = definition_or_stylesheet;
                }
                else if (definition_or_stylesheet.constructor === {}.constructor) {
                    pi = this.getStylesheet(definition_or_stylesheet.href);
                } else {
                    throw (new Error("Not a valid stylesheet"));
                }
                this.selectNodes(`processing-instruction('xml-stylesheet')`).forEach(node => node.isEqualNode(pi) && el.remove());
            }

            var toString_original = Node.prototype.toString;
            Node.prototype.toString = function () {
                //if (this instanceof HTMLElement) {
                //    return toString_original
                //} else {
                return new XMLSerializer().serializeToString(this);
                //}
            }
            if (!Node.prototype.hasOwnProperty('xml')) {
                Object.defineProperty(Node.prototype, 'xml', {
                    get: function () {
                        return this.toString();
                    }
                })
            }

            if (!HTMLElement.prototype.hasOwnProperty('queryChildren')) {
                Object.defineProperty(HTMLElement.prototype, 'queryChildren', {
                    value: function (selector) {
                        return [...this.children].filter((child) => child.matches(selector))
                    },
                    writable: false, enumerable: false, configurable: false
                });
            }

            let original_HTMLTableCellElement = Object.getOwnPropertyDescriptor(HTMLTableCellElement.prototype, 'scope')
            let scope_handler = { /*Estaba con HTMLElement, pero los SVG los ignoraba. Se deja abierto para cualquier elemento*/
                get: function () {
                    if (this.ownerDocument instanceof XMLDocument) return null;
                    let original_PropertyDescriptor = this instanceof HTMLTableCellElement && original_HTMLTableCellElement || {};
                    let self = this;
                    let store = this.store;
                    if (!store) {
                        return null;
                    } else {
                        //let ref = this.parentElement && this.closest && this || this.parentNode || this
                        let ref = this instanceof Element ? this : this.parentNode;
                        let id = ref.id;
                        let dom_scope = !(ref.hasAttribute("[xo-scope]")) && store.find(id) && ref || ref.closest("[xo-scope]") || undefined;
                        let attribute = ref.closest("[xo-attribute]");
                        if (!dom_scope) {
                            return null;
                        } else if (dom_scope.contains(attribute)) {
                            attribute = attribute.getAttribute("xo-attribute");
                        } else {
                            attribute = null;
                        }
                        let node = store.find(dom_scope.getAttribute("xo-scope") || id);
                        if (!attribute && this instanceof Text) attribute = 'text()';
                        if (node && attribute) {
                            if (attribute === 'text()') {
                                [...node.childNodes].filter(el => el instanceof Text).pop() || node.append(node.ownerDocument.createTextNode(node.textContent));
                                return [...node.childNodes].filter(el => el instanceof Text).pop();
                            }
                            else {
                                let attribute_node;
                                attribute_node = node.getAttributeNode(attribute);
                                attribute_node = attribute_node || node.createAttribute(attribute, null);
                                return attribute_node;
                            }
                        }
                        //Implementar para Text $0.$$('ancestor-or-self::*').map(el => el.scope).filter(el => el && el.$('self::xo:r')).pop().getAttributeNode($0.scope.value)
                        return node || original_PropertyDescriptor.get && original_PropertyDescriptor.get.apply(this, arguments) || null;
                    }
                }
            }
            if (!Element.prototype.hasOwnProperty('scope')) {
                Object.defineProperty(Element.prototype, 'scope', scope_handler);
            }
            if (!Text.prototype.hasOwnProperty('scope')) {
                Object.defineProperty(Text.prototype, 'scope', scope_handler);
            }

            //if (!Element.prototype.hasOwnProperty('source')) {
            //    Object.defineProperty(Element.prototype, 'source', Object.getOwnPropertyDescriptor(Element.prototype, 'scope'));
            //}
            Object.defineProperty(HTMLTableCellElement.prototype, 'scope', Object.getOwnPropertyDescriptor(Element.prototype, 'scope'));

            const store_handler = {
                get: function () {
                    if (this.ownerDocument instanceof XMLDocument) {
                        return this.ownerDocument.store
                    } else {
                        let node = this.parentElement && this.closest && this || this.parentNode || this;
                        let store_name = [node.closest && node.closest("[xo-store],[xo-stylesheet]")].map(el => el && el.getAttribute("xo-store") || null)[0];
                        let store = store_name && store_name in xover.stores && xover.stores[store_name] || null;
                        return store;
                    }
                }
            }
            if (!Element.prototype.hasOwnProperty('store')) {
                Object.defineProperty(Element.prototype, 'store', store_handler);
            }
            if (!Text.prototype.hasOwnProperty('store')) {
                Object.defineProperty(Text.prototype, 'store', store_handler);
            }

            if (!Element.prototype.hasOwnProperty('stylesheet')) {
                Object.defineProperty(Element.prototype, 'stylesheet', {
                    get: function () {
                        if (this.ownerDocument instanceof XMLDocument) {
                            return undefined
                        } else {
                            let node = this.parentElement && this || this.parentNode || this;
                            let stylesheet_name = [node.closest("[xo-stylesheet]")].map(el => el && el.getAttribute("xo-stylesheet") || null)[0];
                            return (((node || {}).store || {}).sources || {})[stylesheet_name] || undefined;
                        }
                    }
                });
            }

            if (!Element.prototype.hasOwnProperty('section')) {
                Object.defineProperty(Element.prototype, 'section', {
                    get: function () {
                        if (this.ownerDocument instanceof XMLDocument) {
                            return undefined
                        } else {
                            let node = this.parentElement && this || this.parentNode || this;
                            return node.closest("[xo-stylesheet],[xo-store]")
                        }
                    }
                });
            }

            XMLDocument.prototype.normalizeNamespaces = function () {
                let normalized = xover.xml.normalizeNamespaces(this)
                this.replaceBy(normalized)
                return this;
            }

            Element.prototype.remove = function (settings = {}) {
                if (!this.reactive || settings.silent) {
                    original_remove.apply(this);
                    return this;
                }
                let beforeRemove = new xover.listener.Event('beforeRemove', { target: this, srcEvent: event }, this);
                window.top.dispatchEvent(beforeRemove);
                if (beforeRemove.cancelBubble || beforeRemove.defaultPrevented) return;
                let parentNode = this.parentNode;
                let nextSibling = this.nextSibling;
                let parentElement = this.parentElement;

                //var store = this.ownerDocument.store
                ////this.ownerDocument.store = (this.ownerDocument.store || xover.stores[xover.data.hashTagName(this.ownerDocument)]) /*Se comenta para que quede el antecedente de que puede traer problemas de desempeño este enfoque. Nada grave*/
                //if (store) { /*Asumimos que el store es administrado correctamente por la misma clase. Garantizar que se mantenga la referencia*/
                //    store.takeSnapshot();
                //}
                //let context_store = this.store;
                //if (context_store) {
                //    context_store.save();
                //}
                let event_type = 'remove', node = this;
                let matching_listeners; //= xover.listener.matches(node, event_type);

                original_remove.apply(this, arguments);

                let descriptor = Object.getPropertyDescriptor(this, 'formerParentNode') || { writable: true };
                if (!this.formerParentNode && (descriptor.hasOwnProperty("writable") ? descriptor.writable : true)) {
                    Object.defineProperty(this, 'formerNextSibling', { get: function () { return nextSibling } });
                    Object.defineProperty(this, 'formerParentNode', { get: function () { return parentNode } }); //Si un elemento es borrado, pierde la referencia de parentElement y parentNode, pero con esto recuperamos cuando menos la de parentNode. La de parentElement no la recuperamos para que de esa forma sepamos que es un elemento que está desconectado. Métodos como "closest" dejan de funcionar cuando el elemento ya fue borrado.
                }
                //if (this.ownerDocument.selectSingleNode && store) {
                //    //let refresh = !parent.selectSingleNode('//@state:refresh');
                //    //if (refresh) {
                //    //store = (store || xover.stores[xover.data.hashTagName(this.ownerDocument)])
                //    if (store) {
                //        if (parentElement) {
                //            //parentNode.setAttributeNS(xover.spaces["state"], "state:refresh", "true");
                //            ////parentNode = (parentNode.ownerDocument.store.find(parentNode) || parentNode); //Se quita para que la operación de borrado sólo ocurra en el documento actual
                //            store.render();
                //        } /*else { //Removed because replaceBy removes everything and then inserts new_elements
                //            delete xover.stores[store.tag]
                //        }*/
                //    }
                //    //}
                //    //parentNode.setAttributeNS(null, "state:refresh", "true");
                //    //parentNode.ownerDocument.store = (parentNode.ownerDocument.store || xover.stores[xover.data.hashTagName(parentNode.ownerDocument)]);
                //    //parentNode.setAttributeNS(xover.spaces["state"], "state:refresh", "true");
                //    //return new Promise(resolve => {
                //    //    setTimeout(() => {
                //    //        xover.stores.active.render();
                //    //        resolve(true);
                //    //    }, 50);
                //    //});
                window.top.dispatchEvent(new xover.listener.Event('remove', { listeners: matching_listeners }, this));
                //}
                !(this instanceof HTMLElement) && xover.site.sections.filter(el => el.store && el.store === this.store).forEach((el) => el.render())
                return this;
            }

            var original_removeChild = Node.prototype.removeChild;
            Node.prototype.removeChild = function (child) {
                let parentNode = this;
                original_removeChild.call(this, child);
                let descriptor = Object.getPropertyDescriptor(child, 'formerParentNode') || { writable: true };
                if (!child.parentNode && (descriptor.hasOwnProperty("writable") ? descriptor.writable : true)) {
                    Object.defineProperty(child, 'formerParentNode', { get: function () { return parentNode } }); //Si un elemento es borrado, pierde la referencia de parentElement y parentNode, pero con esto recuperamos cuando menos la de parentNode. La de parentElement no la recuperamos para que de esa forma sepamos que es un elemento que está desconectado. Métodos como "closest" dejan de funcionar cuando el elemento ya fue borrado.
                }
                return child;
            }

            Element.prototype.setAttributes = async function (attributes, refresh, delay) {
                if (!attributes) return;
                if (!isNaN(parseInt(delay))) {
                    await xover.delay(delay);
                }
                self = this
                var responses = [];
                !(attributes.length) && Object.entries(attributes).forEach(([attribute, value]) => {
                    if (self.setAttribute) {
                        responses.push(self.setAttribute(attribute, value, refresh));
                    }
                });
                return responses;
            }

            var original_textContent = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent');
            Object.defineProperty(Node.prototype, 'textContent',
                // Passing innerText or innerText.get directly does not work,
                // wrapper function is required.
                {
                    get: function () {
                        return original_textContent.get.call(this);
                    },
                    set: function (value) {
                        if (this.textContent != value) {
                            original_textContent.set.call(this, value);
                            if (this.namespaceURI && this.namespaceURI.indexOf('www.w3.org') != -1 && this.selectSingleNode(`//xsl:comment/text()[contains(.,'Session stylesheet')]`)) {
                                this.ownerDocument.store.render(); //xover.stores.active.documentElement && xover.stores.active.documentElement.setAttributeNS(xover.spaces["state"], "state:refresh", "true");
                            }
                            return original_textContent.set.call(this, value);
                        } else {
                            return original_textContent.set.call(this, value);
                        }
                    }
                }
            );

            Object.defineProperty(Node.prototype, 'value',
                {
                    get: function () {
                        return this.textContent;
                    },
                    set: function (value) {
                        this.textContent = value;
                    }
                }
            );

            Object.defineProperty(Text.prototype, 'value',
                {
                    get: function () {
                        return this.textContent;
                    },
                    set: function (value) {
                        this.textContent = value;
                    }
                }
            );

            Object.defineProperty(ProcessingInstruction.prototype, 'textContent',
                // Passing innerText or innerText.get directly does not work,
                // wrapper function is required.
                {
                    get: function () {
                        return original_textContent.get.call(this);
                    },
                    set: function (value) {
                        if (this.textContent != value) {
                            this.replaceBy(this.ownerDocument.createProcessingInstruction('xml-stylesheet', value));
                            original_textContent.set.call(this, value);
                            if (this.namespaceURI && this.namespaceURI.indexOf('www.w3.org') != -1 && this.selectSingleNode(`//xsl:comment/text()[contains(.,'Session stylesheet')]`)) {
                                this.ownerDocument.store.render(); //xover.stores.active.documentElement && xover.stores.active.documentElement.setAttributeNS(xover.spaces["state"], "state:refresh", "true");
                            } else if (this.ownerDocument && this.ownerDocument.selectSingleNode && this.ownerDocument.store) {
                                //this.setAttributeNS(xover.spaces["state"], "state:refresh", "true");
                                this.ownerDocument.store.render();
                            }
                            return original_textContent.set.call(this, value);
                        } else {
                            return original_textContent.set.call(this, value);
                        }
                    }
                }
            );

            Object.defineProperty(Array.prototype, 'searchText',
                {
                    value: function (search, { caseSensitive = false, accentSensitive = false, literal = true } = {}) {

                        if (!accentSensitive) {
                            search = search.normalize('NFD').replace(/[\u0300-\u036f]/g, "");
                        }
                        if (literal) {
                            search = search.replace(/[-[\]{}()*+?.,\\^$|#]/g, '\\$&');
                            search = search.replace(/[\s]/g, '\\$&+');
                        }
                        search = new RegExp(search, caseSensitive ? "" : "i");

                        return this.filter(el => el.value && el.value.normalize('NFD').replace(/[\u0300-\u036f]/g, "").match(search) || typeof (el) === 'string' && el.normalize('NFD').replace(/[\u0300-\u036f]/g, "").match(search) || typeof (el.toString) === 'function' && el.toString().normalize('NFD').replace(/[\u0300-\u036f]/g, "").match(search));
                    },
                    writable: true, enumerable: false, configurable: false
                }
            );

            var removeAll = {
                value: function (...args) {
                    let items = this instanceof Array && this || args;
                    args = this instanceof Array && args || [];
                    let removed = [];
                    for (let i = items.length; i > 0; --i) {
                        let el = items.pop();
                        removed.unshift(el);
                        if (typeof (el) == 'object' && el && "remove" in el) {
                            el.remove.apply(el, args);
                        }
                    }
                    return removed;
                },
                writable: false, enumerable: false, configurable: false
            }

            Object.defineProperty(Array.prototype, 'removeAll', removeAll);
            Object.defineProperty(Array.prototype, 'remove', removeAll);

            var element_proxy = new Proxy(Node, {
                get: function (target, name) {
                    return target[name];
                },
                set: async function (target, name, value) {
                    let refresh;
                    if (value && ['object', 'function'].includes(typeof (value))) {
                        throw (new Error('State value is not valid type'));
                    }
                    if (target[name] != value) {
                        refresh = true
                    }
                    target[name] = value
                    var return_value
                    if (refresh) {
                        var name = name, value = value;
                        await self.sources.load();
                        if ([...Object.values(self.sources || {})].filter(stylesheet => {
                            return !!(stylesheet || window.document.createElement('p')).selectSingleNode(`//xsl:stylesheet/xsl:param[@name='state:${name}']`)
                        }).length) {
                            console.log(`Rendering ${document.tag} triggered by state:${name}`);
                            self.render(/*true*/);
                        };
                    }
                }
            })

            if (!Document.prototype.hasOwnProperty('reactive')) {
                Object.defineProperty(Document.prototype, 'reactive', {
                    get: function () {
                        return !(this.disconnected)
                    },
                    enumerable: true,
                    configurable: true
                })
            }

            if (!Element.prototype.hasOwnProperty('reactive')) {
                Object.defineProperty(Element.prototype, 'reactive', {
                    get: function () {
                        return this.ownerDocument.reactive && !(this.disconnected || this.disconnected === undefined && (this instanceof HTMLElement || this instanceof SVGElement || ['http://www.w3.org/1999/XSL/Transform'].includes(this.namespaceURI)))
                    },
                    enumerable: true,
                    configurable: true
                })
            }

            if (!Attr.prototype.hasOwnProperty('reactive')) {
                Object.defineProperty(Attr.prototype, 'reactive', {
                    get: function () {
                        return this.disconnected === undefined ? this.ownerElement && this.ownerElement.reactive : !this.disconnected;
                    },
                    enumerable: true,
                    configurable: true
                })
            }

            if (!Text.prototype.hasOwnProperty('reactive')) {
                Object.defineProperty(Text.prototype, 'reactive', {
                    get: function () {
                        return this.disconnected === undefined ? this.parentElement && this.parentElement.reactive : !this.disconnected;
                    },
                    enumerable: true,
                    configurable: true
                })
            }

            if (!Node.prototype.hasOwnProperty('disconnect')) {
                Object.defineProperty(Node.prototype, 'disconnect', {
                    value: function (reconnect = 1) {
                        this.disconnected = true;
                        if (reconnect) {
                            xover.delay(reconnect).then(async () => {
                                this.connect();
                            });
                        }
                    }
                })
            }

            if (!Node.prototype.hasOwnProperty('connect')) {
                Object.defineProperty(Node.prototype, 'connect', {
                    value: function () {
                        delete this.disconnected
                    }
                })
            }

            if (!Node.prototype.hasOwnProperty('freeze')) {
                Object.defineProperty(Node.prototype, 'freeze', {
                    value: function (reconnect = 1) {
                        this.frozen = true;
                        if (reconnect) {
                            xover.delay(reconnect).then(async () => {
                                this.unfreeze();
                            });
                        }
                    }
                })
            }

            if (!Node.prototype.hasOwnProperty('unfreeze')) {
                Object.defineProperty(Node.prototype, 'unfreeze', {
                    value: function () {
                        delete this.frozen
                    }
                })
            }

            Element.prototype.setAttributeNS = function (namespace, attribute, value, settings = {}) {
                if (!this.reactive || settings.silent) {
                    original_setAttributeNS.call(this, namespace, attribute, value);
                    return this;
                }
                let target = this;
                let attribute_node;
                if (namespace) {
                    let { prefix, name: attribute_name } = xover.xml.getAttributeParts(attribute);
                    attribute_node = target.getAttributeNodeNS(namespace, attribute_name)
                } else {
                    attribute_node = target.getAttributeNode(attribute)
                }

                attribute_node = attribute_node || this.createAttributeNS(namespace, attribute, value);
                attribute_node.value = value;
                return this;
            }

            Element.prototype.setAttribute = function (attribute, value, settings = {}) {
                if (!attribute) return Promise.reject("No attribute set");
                if (attribute instanceof Attr) {
                    value = [value, attribute.value].coalesce();
                    attribute = attribute.name;
                }
                let target = this;
                if (attribute.indexOf(':') != -1) {
                    let { prefix, name: attribute_name } = xover.xml.getAttributeParts(attribute);
                    namespace = this.resolveNS(prefix) || xover.spaces[prefix];
                    target.setAttributeNS(namespace, attribute, value, settings);
                } else {
                    if (!this.reactive || settings.silent) {
                        original_setAttribute.call(this, attribute, value);
                    } else {
                        target.setAttributeNS("", attribute, value, settings);
                    }
                }
                return this;
            }

            Element.prototype.set = function (...args) {
                if (!args.length) return Promise.reject("Nothing to set");
                if (args[0] instanceof Text) {
                    this.textContent = args[0];
                } else if (typeof (args[0]) === 'function') {
                    args[0].apply(this, [this]);
                } else if (typeof (args[0]) === 'string') {
                    if (typeof (args[2]) === 'string') {
                        this.setAttributeNS(args[2], args[0], args[1])
                    } else if (args[1] === undefined) {
                        if (this.hasAttribute(args[0])) {
                            this.removeAttribute(args[0])
                        } else {
                            this.textContent = args[0];
                        }
                    } else if (typeof (args[1]) === 'function') {
                        if (this.hasAttribute(args[0])) {
                            this.setAttribute(args[0], args[1])
                        } else {
                            let attribute = this.createAttribute(args[0], null);
                            attribute.value = args[1]
                        }
                    } else {
                        this.setAttribute.apply(this, [args.shift(), args.shift(), ...args])
                    }
                } else if (args[0] instanceof Attr) {
                    if (typeof (args[args.length - 1]) === 'string') {
                        this.setAttributeNodeNS(args[args.length - 1], args[0])
                    } else {
                        this.setAttributeNode(args[0])
                    }
                } else if (args[0] instanceof Node) {
                    this.append(args[0]);
                } else {
                    return Promise.reject("Couldn't set argument")
                }
                return this;
            }

            var original_getAttribute = Element.prototype.getAttribute;
            var original_getAttributeNS = Element.prototype.getAttributeNS;

            //Element.prototype.getAttribute = function (attribute) {
            //    let target = this;
            //    if (this.ownerDocument && this.ownerDocument.store) {
            //        attribute = attribute.replace(/^@/, "");
            //    }

            //    if (this.hasAttribute(attribute)) {
            //        return original_getAttribute.call(this, attribute)
            //    }

            //    let attribute_node = target.getAttributeNode(attribute);
            //    return attribute_node ? attribute_node.value : null;
            //}

            Element.prototype.getAttributes = function (attributes = []) {
                let node = this;
                let return_attributes = Object.fromEntries(Object.values(node.attributes).filter(el => attributes.includes(el.name) || !attributes.length && el.namespaceURI != xover.spaces["xmlns"]).map(el => [el.name, el.value]))
                return return_attributes;
            }

            Element.prototype.getAttributeNodes = function (attributes = []) {
                let node = this;
                let return_attributes = Object.values(node.attributes).filter(el => attributes.includes(el.name) || !attributes.length && el.namespaceURI != xover.spaces["xmlns"]).map(el => el)
                return return_attributes;
            }

            Element.prototype.attr = function () {
                return this.getAttribute.apply(this, arguments)
            }

            var original_getAttributeNode = Element.prototype.getAttributeNode;
            var original_getAttributeNodeNS = Element.prototype.getAttributeNodeNS;
            Element.prototype.getAttributeNode = function (attribute, namespace) { //TODO: Implement namespace parameter
                //if (typeof (attribute) == 'string') {
                //    attribute = attribute.replace(/^@/, "");
                //}
                attribute = (attribute instanceof Attr ? attribute.value : attribute);

                if (this.hasAttribute(attribute)) {
                    return original_getAttributeNode.call(this, attribute)
                }
                let namespace_URI
                //if ((this.namespaceURI || '').indexOf("http://www.w3.org") !== 0) {
                let { prefix, name: attribute_name } = xover.xml.getAttributeParts(attribute);
                namespace_URI = this.resolveNS(prefix) || xover.spaces[prefix];
                if (namespace_URI) {
                    return original_getAttributeNodeNS.call(this, namespace_URI, attribute_name);
                } else {
                    return original_getAttributeNode.call(this, attribute);
                }

                //}
            }
            Element.prototype.get = Element.prototype.getAttributeNode;
            Element.prototype.getNode = function () { alert("getNode method is deprecated") } //TODO: Deprecate this method

            Element.prototype.createAttribute = function (attribute, value = '') {
                //attribute = attribute.replace(/^@/, "");
                let node = (value === null && this.cloneNode() || this)
                let parentNode = this;
                let new_attribute_node;
                let { prefix, name: attribute_name } = xover.xml.getAttributeParts(attribute);
                let namespace = this.resolveNS(prefix) || xover.spaces[prefix];
                if (!namespace) {
                    original_setAttribute.call(node, attribute, value);
                } else {
                    original_setAttributeNS.call(node, namespace, attribute, value);
                }
                new_attribute_node = original_getAttributeNode.call(node, attribute);
                if (value === null) {
                    original_removeAttribute.call(node, attribute);
                    let descriptor = Object.getPropertyDescriptor(new_attribute_node, 'parentNode') || { writable: true };
                    if (descriptor.hasOwnProperty("writable") ? descriptor.writable : true) {
                        Object.defineProperty(new_attribute_node, 'parentNode', { get: function () { return parentNode } });
                    }
                }
                Object.defineProperty(new_attribute_node, 'nil', { value: true, writable: true, editable: true });
                return new_attribute_node;
            }

            Element.prototype.createAttributeNS = function (namespace_URI, attribute, value = '') {
                //attribute = attribute.replace(/^@/, "");
                let node = (value === null && this.cloneNode() || this)
                let parentNode = this;
                let new_attribute_node;
                if (namespace_URI) {
                    let { prefix, name: attribute_name } = xover.xml.getAttributeParts(attribute);
                    if (!this.hasAttributeNS(namespace_URI, attribute_name)/* && (this.namespaceURI || '').indexOf("http://www.w3.org") !== 0*/) {
                        original_setAttributeNS.call(node, namespace_URI, attribute, value);
                    }
                    new_attribute_node = original_getAttributeNodeNS.call(node, namespace_URI, attribute_name);
                } else {
                    if (!node.hasAttribute(attribute)/* && (node.namespaceURI || '').indexOf("http://www.w3.org") !== 0*/) {
                        original_setAttribute.call(node, attribute, value);
                    }
                    new_attribute_node = original_getAttributeNode.call(node, attribute);
                }
                if (value === null) {
                    original_removeAttribute.call(node, attribute);
                    let descriptor = Object.getPropertyDescriptor(new_attribute_node, 'parentNode') || { writable: true };
                    if (descriptor.hasOwnProperty("writable") ? descriptor.writable : true) {
                        Object.defineProperty(new_attribute_node, 'parentNode', { get: function () { return parentNode } });
                    }
                }

                Object.defineProperty(new_attribute_node, 'nil', { value: true, writable: true, editable: true });
                return new_attribute_node;
            }

            if (!XMLDocument.prototype.hasOwnProperty('body')) {
                Object.defineProperty(XMLDocument.prototype, 'body', {
                    get: function () {
                        if (this instanceof XMLDocument) {
                            return this.documentElement
                        } else {
                            return this.querySelector('body')
                        }
                    }
                });
            }

            Element.prototype.toggleAttribute = function (attribute, value, otherwise_value = null) {
                value = typeof value === 'function' && value.call(this) || value && value.constructor === {}.constructor && JSON.stringify(value) || value != null && String(value) || value;
                if (this.getAttribute(attribute) == value) {
                    this.setAttribute(attribute, otherwise_value)
                } else {
                    this.setAttribute(attribute, value)
                }
                return this;
            }
            //Element.prototype.toggle = Element.prototype.toggleAttribute;

            xover.listener.on('attributeChanged', function ({ target, attribute, value, old: oldValue }) {
            })

            var original_removeAttribute = Element.prototype.removeAttribute;
            var original_removeAttributeNS = Element.prototype.removeAttributeNS;
            Element.prototype.removeAttributeNS = function (namespace_URI, attribute, value, refresh = false) {
                let target = this;
                let attribute_node = target.getAttributeNodeNS(namespace_URI, attribute);
                attribute_node && attribute_node.remove();
            }

            Element.prototype.removeAttribute = async function (attribute, settings = {}) {
                if (!this.reactive || settings.silent) {
                    return_value = original_removeAttribute.call(this, attribute)
                    return this;
                }
                //if (attribute instanceof Attr) {
                //    value = [value, attribute.value].coalesce();
                //    attribute = attribute.name;
                //} else {

                //if (this.ownerDocument && this.ownerDocument.store) {
                //    attribute = attribute.replace(/^@/, "");
                //}
                let attribute_node = this.getAttributeNode(attribute);
                attribute_node && attribute_node.remove();
            }

            //Element.prototype.removeAttribute = function (attribute, refresh) {
            //    if (!this.hasAttribute(attribute)) return;
            //    let attribute_node = this.getAttributeNode(attribute);
            //    let beforeRemove = new xover.listener.Event('beforeRemove', { target: attribute_node, srcEvent: event });
            //    xover.listener.dispatchEvent(beforeRemove, attribute_node);
            //    if (beforeRemove.cancelBubble || beforeRemove.defaultPrevented) return;
            //    if (this.ownerDocument.selectSingleNode && this.ownerDocument.store) {
            //        //if (attribute != 'state:refresh' && (xover.manifest.server || {}).login && !(xover.session.status == 'authorized')) {
            //        //    return;
            //        //}
            //        let { prefix, name: attribute_name } = xover.xml.getAttributeParts(attribute);
            //        var refresh = Array.prototype.coalesce(refresh, !(["xml", "xmlns"].includes(prefix) || attribute == 'state:refresh'));
            //        original_removeAttribute.apply(this, arguments);
            //        if (refresh) {
            //            this.ownerDocument.store.render(refresh);
            //        }
            //        let source = this.ownerDocument.source;
            //        source && source.save();
            //    } else {
            //        original_removeAttribute.apply(this, arguments);
            //    }
            //    xover.listener.dispatchEvent(new xover.listener.Event('remove', { target: attribute_node, element: this, attribute: attribute_node }), this);
            //}

            Attr.prototype.selectSingleNode = function (xpath) {
                return this.ownerDocument.selectSingleNode.apply(this, [xpath]);
            }

            Attr.prototype.getPropertyValue = function (property_name) {
                for (let match of this.value.matchAll(new RegExp(`\\b(${property_name}):([^;]+)`, 'g'))) {
                    return match[2]
                }
            }

            Attr.prototype.setPropertyValue = function (property_name, value) {
                this.value = this.value.replace(new RegExp(`\\b(${property_name}):([^;]+)`, 'g'), (match, property) => `${property}:${value}`)
            }

            //Object.defineProperty(Attr.prototype, 'source', {
            //    get: function () {
            //        return xover.sources[this.nodeName]
            //    }
            //})

            //var original_document_documentElement = Object.getOwnPropertyDescriptor(Document.prototype, 'documentElement');
            //Object.defineProperty(Document.prototype, 'documentElement', {
            //    get: function () {
            //        let _documentElement = original_document_documentElement.get.call(this) || this.source && this.fetch && this.fetch() || null;
            //        return original_document_documentElement.get.call(this);
            //    },
            //    set: function (value) { }
            //});


            //Event.native = {};
            //Event.native.srcElement = Object.getOwnPropertyDescriptor(Event.prototype, 'srcElement');
            //Object.defineProperty(Event.prototype, 'srcElement', {
            //    get: function () {
            //        let return_value = Event.native.srcElement.get.call(this);
            //        return_value.event = this;
            //        return return_value
            //    }
            //})

            var original_attr_value = Object.getOwnPropertyDescriptor(Attr.prototype, 'value');
            Object.defineProperty(Attr.prototype, 'value',
                // Passing innerText or innerText.get directly does not work,
                // wrapper function is required.
                {
                    get: function () {
                        return this.nil ? null : original_attr_value.get.call(this);
                    },
                    set: function (value) {
                        if (this.frozen) return this;
                        if (event && (event.type || "").split(/::/, 1).shift() == 'beforeChange' && this.name == ((event.detail || {}).target || {}).name) {
                            event.preventDefault();
                        }
                        if (typeof value === 'function') {
                            value = value.call(this, this);
                        }
                        if (value instanceof Attr) {
                            value = value.value
                        } else if (value && value.constructor === {}.constructor) {
                            value = JSON.stringify(value)
                        }
                        let target = this;
                        let target_node = this.parentNode;
                        let attribute_name = this.localName;
                        //let store = /*this.store || */this.ownerDocument.store;
                        //let source = store && store.source || null;
                        let old_value = this.value;
                        let return_value;
                        let beforeset_event = new xover.listener.Event('beforeSet', { element: this.parentNode, attribute: this, value: value, old: old_value }, this);
                        window.top.dispatchEvent(beforeset_event);
                        //if (beforeset_event.cancelBubble || beforeset_event.defaultPrevented) return;
                        value = (beforeset_event.detail || {}).hasOwnProperty("returnValue") ? beforeset_event.detail.returnValue : value;
                        if (value != null) {
                            value = `${value}`
                        };

                        if (old_value !== value) {
                            let before = new xover.listener.Event('beforeChange', { element: this.parentNode, attribute: this, value: value, old: old_value }, this);
                            if (!(event && (event.type || "").split(/::/, 1).shift() == 'beforeChange')) {
                                (old_value != value || event && (event.type || "").split(/::/, 1).shift() == 'change') && window.top.dispatchEvent(before);
                            }
                            value = (before.detail || {}).hasOwnProperty("returnValue") ? before.detail.returnValue : value;
                            //if (before.cancelBubble || before.defaultPrevented) return;
                        }
                        if (!this.ownerElement && value !== undefined && value !== null) {
                            original_attr_value.set.call(this, value);
                            this.parentNode.setAttributeNode(this);
                        }
                        if (value === null || value === undefined) {
                            this.nil = true;
                            this.ownerElement && this.remove()
                        } else {
                            this.nil = false;
                            original_attr_value.set.call(this, value);
                        }
                        window.top.dispatchEvent(new xover.listener.Event('set', { element: this.parentNode, attribute: this, value: value, old: old_value }, this));
                        if (old_value !== value) {
                            if (!(old_value === null && this.namespaceURI === 'http://panax.io/xover' && this.localName === 'id')) {
                                window.top.dispatchEvent(new xover.listener.Event('change', { element: this.parentNode, attribute: this, value: value, old: old_value }, this));
                                if ((this.namespaceURI || '').indexOf("http://panax.io/state") != -1 || Object.values(xover.site.get(this.name) || {}).length) {
                                    xover.site.set(this.name, new Object.push(this.parentNode.getAttribute("xo:id"), value))
                                }
                                //let source = this.ownerDocument.source;
                                //source && source.save && source.save();

                                ////let context = ((event || {}).srcEvent || event || {}).target && event.srcEvent.target.closest('*[xo-stylesheet]') || store;
                                ////context && context.render();
                                //let prefixes = Object.entries(xover.spaces).filter(([key, value]) => this.namespaceURI.indexOf(value) == 0).map(([key]) => key);
                                //[...top.document.querySelectorAll('[xo-stylesheet]'), ...top.document.querySelectorAll(`[xo-attribute="${this.name}"]`)].filter(el => el.store === store).filter(el => el.get('xo-attribute') || el.stylesheet.$(`xsl:stylesheet/xsl:param[@name="${this.name}"]${prefixes.map(prefix => `|xsl:stylesheet/xsl:param[@name="${prefix}:dirty"]`).join('')}`)).forEach((el) => el.render())
                            }
                        }
                        return return_value;

                    }
                }
            );

            Object.defineProperty(Attr.prototype, 'get', {
                value: function (name) {
                    return this.nodeName == (name || this.nodeName) && this.value || null;
                }
            });

            var original_node_namespaceURI = Object.getOwnPropertyDescriptor(Node.prototype, 'namespaceURI');
            Object.defineProperty(Node.prototype, 'namespaceURI',
                {
                    get: function () {
                        return original_node_namespaceURI && original_node_namespaceURI.get.call(this) || "";
                    },
                    set: function (value) {
                        return original_node_namespaceURI && original_node_namespaceURI.set.call(this);

                    }
                }
            );

            var original_attr_namespaceURI = Object.getOwnPropertyDescriptor(Attr.prototype, 'namespaceURI');
            Object.defineProperty(Attr.prototype, 'namespaceURI',
                {
                    get: function () {
                        return original_attr_namespaceURI.get.call(this) || "";
                    },
                    set: function (value) {
                        return original_attr_namespaceURI.set.call(this);

                    }
                }
            );

            var original_HTMLTextAreaElement_value = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value');
            var original_HTMLSelectElement_value = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value');
            var value_handler = {
                get: function () {
                    let original_handler = eval(`original_${this.constructor.name}_value`)
                    return original_handler.get.call(this);
                },
                set: function (value) {
                    let original_handler = eval(`original_${this.constructor.name}_value`)
                    let return_value = original_handler.set.call(this, [value]);
                    this.dispatchEvent(new Event('change'));
                    return return_value;
                }
            }

            Object.defineProperty(HTMLTextAreaElement.prototype, 'value', value_handler);
            Object.defineProperty(HTMLSelectElement.prototype, 'value', value_handler);

            Attr.prototype.set = function (value) {
                this.value = value;
                return this;
            }

            Object.defineProperty(Comment.prototype, 'metadata', {
                get: function () {
                    let info = xo.xml.createNode(this.data);
                    return `template ${info.textContent.replace(/\n/g, '')}`
                }
            });

            Object.defineProperty(Comment.prototype, 'source', {
                get: function () {
                    let info = xo.xml.createNode(this.data.replace(/- -/g, '--'));
                    let attributes = xo.json.fromAttributes(info.textContent);
                    let xpath = Object.entries(attributes).map(([key, value]) => `@${key}="${value}"`).join(' and ');
                    let source = xo.sources[info.getAttribute("file")].cloneNode(true);
                    source.select(`//xsl:comment[contains(.,'<template')]`).remove();
                    let matches = source.selectNodes(`//xsl:template[${xpath}]`);
                    let node = matches.pop();
                    return node;
                }
            });

            Comment.prototype.set = function (value) {
                if (this.textContent !== "ack:no_match") {
                    this.textContent = value
                }
                return this;
            }

            Comment.prototype.get = function (value) {
                if (this.textContent === value) {
                    return this.ownerDocument.createTextNode(this.textContent);
                }
                return null;
            }

            Element.prototype.has = function (attribute_name) {
                return !!this.getAttributeNode(attribute_name);
            }

            Attr.prototype.toggle = function (value, else_value = '') {
                value = typeof value === 'function' && value.call(this, this.value) || value && value.constructor === {}.constructor && JSON.stringify(value) || value != null && String(value) || value;
                //if (this.value != value) {
                this.parentNode.store && this.parentNode.store.render();
                //}
                if (this.value == value) {
                    this.value = else_value
                } else {
                    this.value = value
                }
                let source = this.ownerDocument.source;
                source && source.save();
                return this;
            }

            Text.prototype.reactive = function (value) {
            }

            Text.prototype.set = function (value) {
                value = typeof value === 'function' && value(this) || value && value.constructor === {}.constructor && JSON.stringify(value) || value != null && String(value) || value;
                let new_value = this.ownerDocument.createTextNode(value);
                if (this.reactive) {
                    let old_value = this.textContent;
                    let before_set = new xover.listener.Event('beforeSet', { element: this.parentNode, attribute: this, value: new_value, old: old_value }, this);
                    window.top.dispatchEvent(before_set);
                    if (before_set.defaultPrevented || event.cancelBubble) return;
                    if (old_value == new_value) return;
                    let before = new xover.listener.Event('beforeChange', { element: this.parentNode, attribute: this, value: new_value, old: old_value }, this);
                    window.top.dispatchEvent(before);
                }
                this.textContent = new_value;
                return this;
            }

            if (!Attr.prototype.hasOwnProperty('parentNode')) {
                Object.defineProperty(Attr.prototype, 'parentNode', {
                    get: function () {
                        return this.ownerElement;
                    }
                })
            }

            let original_ProcessingInstruction_remove = ProcessingInstruction.prototype.remove;
            ProcessingInstruction.prototype.remove = function (refresh = true) {
                original_ProcessingInstruction_remove.apply(this, arguments);
                if (this.ownerDocument && this.ownerDocument.store) {
                    [document.querySelector(`[xo-store="${this.ownerDocument.store.tag}"][xo-stylesheet='${xover.json.fromAttributes(this.textContent)["href"]}']`)].map(el => el && el.remove());
                    this.ownerDocument.store.removeStylesheet(this);
                    if (refresh) {
                        this.ownerDocument.store.render();
                    }
                }
            }

            ProcessingInstruction.prototype.replaceBy = function (new_element) {
                if (new_element !== this) {
                    this.parentNode.insertBefore(new_element, this);
                    return original_ProcessingInstruction_remove.apply(this, arguments);
                } else {
                    return this;
                }
            }

            Node.prototype.replace = function (new_node) {
                new_node = (new_node.documentElement || new_node)
                return this.parentNode && this.parentNode.replaceChild(new_node/*.cloneNode(true)*/, this) || new_node;
            }

            let original_attr_replace = Attr.prototype.replace
            Attr.prototype.replace = function (...args) {
                if (args[0] instanceof Attr) {
                    return original_attr_replace.apply(this, args)
                } else if (typeof (args[0]) == 'string' || args[0] instanceof RegExp) {
                    this.value = this.value.replace(args[0], args[1])
                    return this;
                }
            }

            if (typeof Node.prototype.replaceChildren !== 'function') {
                Node.prototype.replaceChildren = function (...nodes) {
                    while (this.firstChild) {
                        this.firstChild.remove();
                    }
                    if (nodes && nodes.length) {
                        this.appendChild(...nodes);
                    }
                };
            }

            Node.prototype.replaceBy = function (new_node) {
                let parent_node = this.parentNode;
                if (!parent_node) {
                    return new_node
                }
                new_node = (new_node.documentElement || new_node);
                return this.parentNode.replaceChild(new_node.cloneNode(true), this);
            }

            var original_replaceWith = Object.getOwnPropertyDescriptor(Element.prototype, 'replaceWith');
            Object.defineProperty(Element.prototype, 'replaceWith', {
                value: function (...args) {
                    let new_node = args[0];
                    if (!new_node) return;
                    original_replaceWith.value.apply(this, [new_node])
                    return new_node;
                }
            })

            XMLDocument.prototype.replaceBy = function (new_document) {
                if (new_document !== this) {
                    while (this.firstChild) {
                        this.removeChild(this.lastChild);
                    }
                    if (new_document.childNodes) {
                        for (node of new_document.childNodes) {
                            if (node.nodeType === Node.DOCUMENT_TYPE_NODE) {
                                this.appendChild(node)
                            }
                        }
                        this.append(...new_document.childNodes.toArray().filter(node => ![3, 10].includes(node.nodeType)))
                    }
                }
                return this;
            }

            Node.prototype.replaceChild = function (new_node, target, refresh = true) {
                new_node = (new_node.documentElement || new_node);
                let beforeEvent = new xover.listener.Event('beforeAppendTo', { target: this.parentElement, srcEvent: event }, this.parentElement);
                window.top.dispatchEvent(beforeEvent);
                if (beforeEvent.cancelBubble || beforeEvent.defaultPrevented) return;
                if ((this.ownerDocument || this) instanceof XMLDocument) {
                    let store = this.store;
                    //if ((xover.manifest.server || {}).login && !(xover.session.status == 'authorized')) {
                    //    return;
                    //}
                    ////var refresh = (refresh ?? !!xover.stores.getActive()[this.ownerDocument.store.tag]);
                    //this.ownerDocument.documentElement.setAttributeNS(xover.spaces["state"], 'state:refresh', 'true', refresh);
                    let result = replaceChild_original.apply(this, [new_node, target]);
                    if (this.selectSingleNode(`//xsl:comment/text()[contains(.,'Session stylesheet')]`)) {
                        /*Update of session variables*/
                        let attribute = new_node;
                        Object.values(xover.stores).map(store => {
                            (store.documentElement || document.createElement("p")).setAttribute(attribute.getAttribute("name"), attribute.textContent.replace(/[\s]+$/, ''));
                        });
                    }
                    if (refresh && store) store.render()
                } else {
                    replaceChild_original.apply(this, [new_node, target]);
                }
                window.top.dispatchEvent(new xover.listener.Event('appendTo', { target: this.parentElement, srcEvent: event }, this.parentElement));
                return new_node;
            }

            Attr.prototype.remove = function (settings = {}) {
                if (!this.reactive || settings.silent) {
                    if (this.namespaceURI) {
                        return_value = original_removeAttributeNS.call(this.parentNode, this.namespaceURI, this.localName)
                    } else {
                        return_value = original_removeAttribute.call(this.parentNode, this.name)
                    }
                    return this;
                }
                let parentNode = this.parentNode;
                let ownerElement = this.ownerElement;
                if (ownerElement) {
                    let return_value;
                    let event_type = 'remove', node = this;
                    let matching_listeners; //= xover.listener.matches(node, event_type);
                    if (this.namespaceURI) {
                        return_value = original_removeAttributeNS.call(this.parentNode, this.namespaceURI, this.localName)
                    } else {
                        return_value = original_removeAttribute.call(this.parentNode, this.name)
                    }
                    let descriptor = Object.getPropertyDescriptor(this, 'parentNode') || { writable: true };
                    if (!(this.parentNode) && (descriptor.hasOwnProperty("writable") ? descriptor.writable : true)) {
                        Object.defineProperty(this, 'parentNode', { get: function () { return parentNode } }); //Si un elemento es borrado, pierde la referencia de ownerElement y parentNode, pero con esto recuperamos cuando menos la de parentNode. La de parentElement no la recuperamos para que de esa forma sepamos que es un elemento que está desconectado. Métodos como "closest" dejan de funcionar cuando el elemento ya fue borrado.
                    }
                    this.value = null;
                    window.top.dispatchEvent(new xover.listener.Event('remove', { listeners: matching_listeners }, this));
                    return return_value;
                }
            }

            Element.prototype.getNamespaces = function () {
                return Object.fromEntries([this, ...this.querySelectorAll("*")].map(el => [...el.attributes].filter(attr => attr.namespaceURI === 'http://www.w3.org/2000/xmlns/')).flat(Infinity).map(attr => [attr.localName, attr.value]));
            }

            var original_insertBefore = Element.prototype.insertBefore
            Element.prototype.insertBefore = function (new_node, settings = {}) {
                if ((this.ownerDocument || this) instanceof XMLDocument) {
                    //if ((xover.manifest.server || {}).login && !(xover.session.status == 'authorized')) {
                    //    return;
                    //}
                    original_insertBefore.apply(this, arguments);
                    if (this.selectSingleNode(`//xsl:comment/text()[contains(.,'Session stylesheet')]`)) {
                        /*Update of session variables*/
                        let attribute = new_node;
                        Object.values(xover.stores).map(store => {
                            (store.documentElement || document.createElement("p")).setAttribute(attribute.getAttribute("name"), attribute.textContent.replace(/[\s]+$/, ''));
                        });
                    }
                    if (this.ownerDocument.store) {
                        this.ownerDocument.store.render();
                    }
                    window.top.dispatchEvent(new xover.listener.Event('change', { node: this }, this));
                    window.top.dispatchEvent(new xover.listener.Event('insert', { node: this }, this));
                } else {
                    original_insertBefore.apply(this, arguments);
                }
            }

            var original_append = Element.prototype.append
            Element.prototype.append = function (...args) {
                if (this.frozen) return this;
                if (!args.length) return;
                let settings = {};
                if ((args[args.length - 1] || '').constructor === {}.constructor) {
                    settings = args.pop();
                }
                if (!this.reactive || settings.silent) {
                    try {
                        original_append.apply(this, args);
                    } catch (e) {
                        if (e.name == 'RangeError') {
                            let array = args
                            let chunkSize = 9999;
                            let index = 0;
                            while (index < array.length) {
                                original_append.apply(this, (array.slice(index, index + chunkSize)));
                                index += chunkSize;
                            }
                        }
                    }
                    return args;
                }
                if (!(args.length)) return [];
                args.forEach(el => {
                    let beforeEvent = new xover.listener.Event('beforeAppend', { target: this, args: args }, el);
                    window.top.dispatchEvent(beforeEvent);
                    if (beforeEvent.cancelBubble || beforeEvent.defaultPrevented) el.remove();
                })
                let beforeEvent = new xover.listener.Event('beforeAppendTo', { target: this, args: args, srcEvent: event }, this);
                window.top.dispatchEvent(beforeEvent);
                if (beforeEvent.cancelBubble || beforeEvent.defaultPrevented) return;
                original_append.apply(this, args);
                if (!(this instanceof HTMLElement) && this.store) this.reseed();
                return args;
            }

            var original_isEqualNode = Element.prototype.isEqualNode
            Element.prototype.isEqualNode = function (ref) {
                return original_isEqualNode.apply(this, [ref]) || this.getAttribute("xo:id") && ref && this.getAttribute("xo:id") == ref.getAttribute("xo:id");
            }

            Node.prototype.appendAfter = function (new_node) {
                this.parentNode.insertBefore((new_node.documentElement || new_node), this.nextElementSibling);
            }

            Node.prototype.appendBefore = function (new_node) {
                this.parentNode.insertBefore((new_node.documentElement || new_node), this);
            }

            Node.prototype.insertFirst = function (new_node) {
                let e = this;
                e.insertBefore((new_node.documentElement || new_node), e.firstChild);
            }

            Node.prototype.insertAfter = function (i, p) {
                let e = this;
                if (e && e.nextElementSibling) {
                    e.parentNode.insertBefore(i, e.nextElementSibling);
                } else {
                    (p || (e || {}).parentNode).appendChild(i);
                }
            }

            Node.prototype.moveTo = function (target, position = 'child') {
                let source = this;
                switch (position) {
                    case 'child':
                        target.appendChild(source);
                        break;
                    case 'before':
                        target.appendBefore(source)
                        break;
                    case 'after':
                        target.appendAfter(source)
                        break;
                    default:
                        throw (new Error('Invalid option'));
                }
            }

            Node.prototype.duplicate = function (reseed = true) {
                let new_node = this.cloneNode(true);
                this.appendAfter(new_node);
                if (reseed) {
                    new_node.selectNodes('.//@xo:id').remove();
                    new_node = new_node.reseed();
                }
                return new_node;
            }

            XMLDocument.prototype.reseed = function () {
                this.documentElement && this.documentElement.reseed();
                return this;
            }

            let originalCloneNode = XMLDocument.prototype.cloneNode;
            XMLDocument.prototype.cloneNode = function (...args) {
                let cloned_element = originalCloneNode.apply(this, args);
                cloned_element.source = this.source;
                cloned_element.store = this.store;
                cloned_element.href = this.href;
                cloned_element.url = this.url;
                return cloned_element;
            }

            Element.prototype.reseed = function (forced) {
                //if (navigator.userAgent.indexOf("Safari") == -1) {
                //    this = xover.xml.transform(this, "xover/normalize_namespaces.xslt");
                //}
                //try {
                if (forced) {
                    this.selectNodes('.//@xo:id').remove()
                }
                this.selectNodes(`descendant-or-self::*[not(@xo:id!="")]`).forEach(node => original_setAttributeNS.call(node, xover.spaces["xo"], 'xo:id', (function (node) { return `${node.nodeName}_${xover.cryptography.generateUUID()}`.replace(/[:-]/g, '_') })(node)));
                //} catch (e) {
                //    this.selectNodes(`descendant-or-self::*[not(@xo:id!="")]`).setAttributeNS(xover.spaces["xo"], 'xo:id', (function () { return `${(this.nodeName}_${xover.cryptography.generateUUID()}`.replace(/[:-]/g, '_') }));
                //}
                return this;
            }

            //if (!Node.prototype.hasOwnProperty('clone')) {
            //    Object.defineProperty(Node.prototype, 'clone', {
            //        value: function (deep) {
            //            let cloned = this.cloneNode(deep);
            //            cloned.copyPropertiesFrom(this);
            //            return cloned;
            //        }
            //    })
            //}

            if (!Node.prototype.hasOwnProperty('copyPropertiesFrom')) {
                Object.defineProperty(Node.prototype, 'copyPropertiesFrom', {
                    value: function (source) {
                        //let target = this;
                        //for (let prop in source.prototype) {
                        //    let prop_desc = Object.getOwnPropertyDescriptor(target, prop) || { writable: true };
                        //    if (prop_desc.writable) {
                        //        Object.defineProperty(target, prop, {
                        //            value: source[prop],
                        //            writable: true, enumerable: true, configurable: false
                        //        });
                        //    }
                        //}
                        //if (Object.getPrototypeOf(source) instanceof this.constructor) {
                        //    this.prototype.copyPropertiesFrom.apply(this, Object.getPrototypeOf(source.constructor))
                        //}

                        //for (let prop in current_source) {
                        //    let source_desc = Object.getPropertyDescriptor(current_source, prop);
                        //    let prop_desc = Object.getOwnPropertyDescriptor(target, prop) || source_desc && [source_desc.writable, source_desc.configurable, true].coalesce();
                        //    if (source_desc && prop_desc) {
                        //        Object.defineProperty(target, prop, {
                        //            value: source[prop]
                        //            , writable: [prop_desc.writable, source_desc.writable].coalesce()
                        //            , enumerable: [prop_desc.enumerable, source_desc.enumerable].coalesce()
                        //            , configurable: [prop_desc.configurable, source_desc.configurable].coalesce()
                        //        });
                        //    }
                        //}

                        let current_source = source;
                        let target = this;

                        for (let prop in current_source) {
                            let prop_desc = Object.getPropertyDescriptor(current_source, prop);
                            //console.log(`Copied ${prop}`)
                            if (!prop_desc) {
                                continue;
                            } else if (prop_desc.value) {
                                Object.defineProperty(this, prop, {
                                    value: function () { return current_source[prop].apply(current_source, arguments) }
                                    , enumerable: true, configurable: false
                                });
                            } else if (prop_desc.get) {
                                Object.defineProperty(this, prop, {
                                    get: function () { return current_source[prop] }
                                    , enumerable: true, configurable: false
                                });
                            }
                        }
                        return target;
                    }
                })
            }

            if (!Node.prototype.hasOwnProperty('transform')) {
                Object.defineProperty(Node.prototype, 'transform', {
                    value: function (xml_document) {
                        let self = this;
                        if (xml_document instanceof Document && !xml_document.documentElement && xml_document.source) {
                            return new Promise(async (resolve, reject) => {
                                try {
                                    let result = self.transform(await xml_document.source.fetch().catch(e => Promise.reject(e)))
                                    return resolve(result);
                                } catch (e) {
                                    return reject(e)
                                }
                            })
                        }
                        if (xml_document instanceof Promise) {
                            return xml_document.then((document) => self.transform(document));
                        }
                        if (typeof (xml_document) == "string") {
                            let xsl = xml_document;
                            if (xsl in xover.sources) {
                                xml_document = xover.sources[xsl];
                            } else if (xsl in xover.sources.defaults) {
                                xml_document = xover.sources.defaults[xsl];
                            } else {
                                if (xover.browser.isIphone()) { //Probablemente esto tiene que cambiar
                                    return this.transform(xover.sources.load(xsl));
                                    //(async () => {
                                    //    xover.sources[xsl] = await xover.fetch.xml(xsl);
                                    //    xsl = xover.sources[xsl];
                                    //})();
                                } else {
                                    xml_document = xover.xml.createDocument(`                          
                <xsl:stylesheet version="1.0"                        
                    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                    <xsl:import href="${xsl}" />
                </xsl:stylesheet>`);
                                }
                            }
                        }
                        if (xml_document && !((xml_document.ownerDocument || xml_document) instanceof XMLDocument)) {
                            throw (new Error("Document must be a valid xml document."));
                        };
                        if (this.selectSingleNode('xsl:*') && !(xml_document && xml_document.selectSingleNode('xsl:*'))) {//Habilitamos opción para que un documento de transformación pueda recibir un documento para transformar (Proceso inverso)
                            return (xml_document || xover.xml.createDocument(`<xo:empty xmlns:xo="http://panax.io/xover"/>`).reseed()).transform(this);
                        }
                        let xsl = xml_document;
                        let xml = this.cloneNode(true);
                        var xmlDoc;
                        var result = undefined;
                        if (!xsl/* && ((arguments || {}).callee || {}).caller != Node.prototype.transform*/) {
                            //return new Promise(async (resolve, reject) => {
                            //    return resolve(self.transform(await xml_document.source.fetch()));
                            //})
                            for (let stylesheet of xml.stylesheets) {
                                xml = xml.transform(stylesheet.document || stylesheet.href);
                            }
                            return xml;
                        }
                        //if (!(xml && xsl)) {
                        //    return xml;//false;
                        //}
                        var original_doc = xml;
                        if (!(typeof (xsl.selectSingleNode) != 'undefined' && xsl.selectSingleNode('xsl:*'))) {
                            throw (new Error("XSL document is empty or invalid"));
                        }
                        if (!xml.selectSingleNode("self::*|*|comment()") && xml.createComment) {
                            xml = xml.cloneNode(true);
                            xml.appendChild(xml.createComment("empty"))
                        }

                        if (document.implementation && document.implementation.createDocument) {
                            let xsltProcessor = new XSLTProcessor();
                            try {
                                if (navigator.userAgent.indexOf("Firefox") != -1) {
                                    var invalid_node = xsl.selectSingleNode("//*[contains(@select,'namespace::')]");
                                    if (invalid_node) {
                                        console.warn('There is an unsupported xpath in then file');
                                    }
                                }
                                //if (navigator.userAgent.indexOf("iPhone") != -1 || xover.debug["xover.xml.consolidate"]) {
                                //    xsl = xover.xml.consolidate(xsl); //Corregir casos cuando tiene apply-imports
                                //}

                                xsltProcessor.importStylesheet(xsl);
                                xsl.selectNodes(`//xsl:stylesheet/xsl:param[starts-with(@name,'js:') or not(contains(@name,':'))][text()]`).map(param => {
                                    try {
                                        xsltProcessor.setParameter(null, param.getAttribute("name"), eval(param.textContent))
                                    } catch (e) {
                                        //xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                                        Promise.reject(e.message);
                                        xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                                    }
                                });
                                xsl.selectNodes(`//xsl:stylesheet/xsl:param[starts-with(@name,'session:')]`).map(param => {
                                    try {
                                        let param_name = param.getAttribute("name").split(":").pop();
                                        if (!(param_name in xover.session)) xover.session[param_name] = [eval(`(${param.textContent !== '' ? param.textContent : undefined})`), ''].coalesce();
                                        let session_value = xover.session.getKey(param.getAttribute("name").split(/:/).pop());
                                        if (session_value !== undefined) {
                                            xsltProcessor.setParameter(null, param.getAttribute("name"), session_value);
                                        }
                                    } catch (e) {
                                        //xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                                        Promise.reject(e.message);
                                    }
                                });
                                xsl.selectNodes(`//xsl:stylesheet/xsl:param[starts-with(@name,'state:')]`).map(param => {
                                    try {
                                        let key = param.getAttribute("name").split(/:/).pop()
                                        let state_value = xover.stores.active.state[key] || xover.site[key];
                                        if (state_value !== undefined) {
                                            xsltProcessor.setParameter(null, param.getAttribute("name"), state_value);
                                        }
                                    } catch (e) {
                                        //xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                                        Promise.reject(e.message);
                                    }
                                });
                                xsl.selectNodes(`//xsl:stylesheet/xsl:param[starts-with(@name,'site:')]`).map(param => {
                                    try {
                                        let key = param.getAttribute("name").split(/:/).pop()
                                        let param_value = xover.site[key] || xover.site[key];
                                        if (param_value !== undefined) {
                                            xsltProcessor.setParameter(null, param.getAttribute("name"), param_value);
                                        }
                                    } catch (e) {
                                        //xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                                        Promise.reject(e.message);
                                    }
                                });
                                for (let param_name of xsl.selectNodes(`//xsl:stylesheet/xsl:param/@name`).filter(name => this.target && this.target.getAttribute(name.value))) {
                                    let param = param_name.parentNode;
                                    let prefix = param_name.prefix || '';
                                    param_name = param_name.value;

                                    xsltProcessor.setParameter(null, param_name, this.target.getAttribute(param_name))
                                }

                                ////if (!xml.documentElement) {
                                ////    xml.appendChild(xover.xml.createDocument(`<xo:empty xmlns:xo="http://panax.io/xover"/>`).documentElement)
                                ////}
                                let tag = xml.tag || `#${xsl.href}`;
                                xml.tag = tag;
                                let listeners = xover.listener.matches(xml, 'beforeTransform')
                                window.top.dispatchEvent(new xover.listener.Event('beforeTransform', { listeners: listeners, document: xml, store: xml.store, stylesheet: xsl }, this));
                                xml = this.cloneNode(true);
                                let timer_id = `${xsl.href || "Transform"}-${Date.now()}`;
                                if (xover.session.debug || xsl.selectSingleNode('//xsl:param[@name="debug:timer" and text()="true"]')) {
                                    console.time(timer_id);
                                }
                                if (xsl.documentElement.getAttribute("xmlns") && !(xsl.selectSingleNode('//xsl:output[@method="html"]')) /*xover.browser.isIOS()*/) {// && ((result || {}).documentElement || {}).namespaceURI == "http://www.w3.org/1999/xhtml" ) {
                                    let transformed = xsltProcessor.transformToFragment(xml, document);
                                    let newDoc;
                                    if (transformed && transformed.children.length > 1) {
                                        newDoc = transformed;
                                    } else if (transformed) {
                                        newDoc = document.implementation.createDocument("http://www.w3.org/XML/1998/namespace", "", null);
                                        newDoc.replaceBy(transformed)
                                    }
                                    result = newDoc;
                                }
                                if (result == null) {
                                    result = xsltProcessor.transformToDocument(xml);
                                }
                                result && [...result.children].map(el => el instanceof HTMLElement && el.$$('//@*[starts-with(., "`") and substring(., string-length(.))="`"]').map(val => { try { val.value = eval(val.value.replace(/\$\{\}/g, '')) } catch (e) { console.log(e) } }));
                                if (!(result && result.documentElement) && !xml.documentElement) {
                                    xml.appendChild(xover.xml.createNode(`<xo:empty xmlns:xo="http://panax.io/xover"/>`).reseed())
                                    return Promise.reject(xml.transform("empty.xslt"));
                                }
                                if (result) result.tag = tag;
                                if ((xover.session.debug || {})["transform"] || xsl.selectSingleNode('//xsl:param[@name="debug:timer" and text()="true"]')) {
                                    console.timeEnd(timer_id);
                                }
                            } catch (e) {
                                return Promise.reject(e)
                                //let default_document = xover.sources.defaults[(xsl.selectSingleNode("//xsl:import") || document.createElement('p')).getAttribute("href")];
                                //if (default_document /*&& arguments.callee.caller != xover.xml.transform*/) {
                                //    result = xml.transform(default_document);
                                //} else if (!xml.documentElement) {
                                //    return xml;
                                //} else {
                                //    console.error("xover.xml.transform: " + (e.message || e.name || e)); //TODO: No está entrando en esta parte, por ejemplo cuando hay un error 404. net::ERR_ABORTED 404 (Not Found)
                                //    return xml;
                                //}
                            }
                            if (!result) {
                                if (/*((arguments || {}).callee || {}).caller != xover.xml.transform && */xsl.selectSingleNode('//xsl:import[@href="login.xslt"]')) {
                                    result = xml.transform(xover.sources.defaults["login.xslt"]);
                                } else if (/*((arguments || {}).callee || {}).caller != xover.xml.transform && */xsl.selectSingleNode('//xsl:import[@href="shell.xslt"]')) {
                                    result = xml.transform(xover.sources.defaults["shell.xslt"]);
                                } else if (!xml.documentElement) {
                                    return xml;
                                } else {
                                    throw (new Error(xover.messages.transform_exception || "There must be a problem with the transformation file. A misplaced attribute, maybe?")); //Podría ser un atributo generado en un lugar prohibido. Se puede enviar al servidor y aplicar ahí la transformación //TODO: Hacer una transformación del XSLT para identificar los problemas comúnes.
                                    result = xml;
                                }
                            }
                            else if (typeof (result.selectSingleNode) == "undefined" && result.documentElement) {
                                result = xover.xml.createDocument(result.documentElement);
                            }
                            [...result.querySelectorAll('parsererror div')].map(message => {
                                if (String(message.textContent).match(/prefix|prefijo/)) {
                                    var prefix = (message.textContent).match(/(?:prefix|prefijo)\s+([^\s]+\b)/).pop();
                                    if (!xover.spaces[prefix]) {
                                        var message = xover.data.createMessage(message.textContent.match("(error [^:]+):(.+)").pop());
                                        xml.documentElement.appendChild(message.documentElement);
                                        return xml;
                                    }
                                    (xml.documentElement || xml).setAttributeNS('http://www.w3.org/2000/xmlns/', "xmlns:" + prefix, xover.spaces[prefix]);
                                    result = xml.transform(xsl);
                                    return result;
                                } else if (String(message.textContent).match(/Extra content at the end of the document/)) {
                                    message.remove();
                                } else if (String(message.textContent).match(/Document is empty/)) {
                                    if (xsl.documentElement.selectNodes('xsl:template').length == 1 && xsl.documentElement.selectNodes('xsl:template[not(*) and text()]')) {
                                        message.textContent = `Template can't return text without a wrapper`
                                    }
                                }
                            });
                        }
                        try {
                            //if (((arguments || {}).callee || {}).caller != xover.xml.transform) {
                            window.top.dispatchEvent(new xover.listener.Event('transform', { original: xml, tag: result.tag, result, transformed: result }, result));
                            //}
                        } catch (e) { }
                        return result
                    },
                    writable: false, enumerable: false, configurable: false
                });
            }

            //if (!XMLDocument.prototype.hasOwnProperty('tag')) {
            //    Object.defineProperty(XMLDocument.prototype, 'tag', {
            //        get: function () {
            //            return this.store && this.store.tag || "";//xover.stores.active.tag;
            //        }
            //    });
            //}

            let stylesheet_renderer_handler = async function () {
                this._render_manager = this._render_manager || xover.delay(1).then(async () => {
                    let selector = this.ownerDocument.contains(this) && this.selector || undefined;
                    let section = selector && this.closest("[xo-stylesheet]");
                    if (section) {
                        let stylesheet = this.getAttribute("xo-stylesheet");
                        let target_store = this.store;
                        if (target_store) {
                            if (!stylesheet) {
                                return this.store.render();
                            } else {
                                let target_document = target_store && target_store.document;
                                return target_document && target_document.render(target_document.createProcessingInstruction('xml-stylesheet', { type: 'text/xsl', href: stylesheet, target: selector, action: "replace" })) || null;
                            }
                        } else {
                            let document = xo.sources[stylesheet];
                            return document.render();
                        }
                    }
                }).finally(async () => {
                    this._render_manager = undefined;
                });
                return this._render_manager;
            }

            if (!HTMLElement.prototype.hasOwnProperty('render')) {
                Object.defineProperty(HTMLElement.prototype, 'render', {
                    value: stylesheet_renderer_handler
                });
            }

            if (!SVGElement.prototype.hasOwnProperty('render')) {
                Object.defineProperty(SVGElement.prototype, 'render', {
                    value: stylesheet_renderer_handler
                });
            }

            if (!HTMLDocument.prototype.hasOwnProperty('render')) {
                Object.defineProperty(HTMLDocument.prototype, 'render', {
                    value: function () {
                        xover.dom.createDialog(this)
                    }
                });
            }

            var original_pushState = Object.getOwnPropertyDescriptor(History.prototype, 'pushState');
            Object.defineProperty(History.prototype, 'pushState', {
                value: function (...args) {
                    let before = new xover.listener.Event('beforePushstate', { state: args[0] }, this)
                    window.top.dispatchEvent(before);
                    if (before.cancelBubble || before.defaultPrevented) return;
                    let response = original_pushState.value.apply(this, [JSON.parse(JSON.stringify(args[0])), args[1], args[2]]);
                    window.top.dispatchEvent(new xover.listener.Event('pushstate', { state: args[0] }, this));
                    return response;
                }
            });

            if (!Location.prototype.hasOwnProperty('tag')) {
                Object.defineProperty(Location.prototype, 'tag', {
                    get: function () {
                        return '#' + xover.URL(this.hash.replace(/^#/, '')).pathname.replace(/^\//, '')
                    }
                });
            }

            if (!URL.prototype.hasOwnProperty('tag')) {
                Object.defineProperty(URL.prototype, 'tag', {
                    get: function () {
                        return '#' + xover.URL(this.hash.replace(/^#/, '')).pathname.replace(/^\//, '')
                    }
                });
            }

            //if (!XMLDocument.prototype.hasOwnProperty('save')) {
            //    Object.defineProperty(XMLDocument.prototype, 'save', {
            //        value: async function () {
            //            if (this.href) {
            //                xover.storehouse.write('sources', this.href, this.toString());
            //            } else {
            //                console.warn("File can't be saved on storehouse if lacks of href property")
            //            }
            //        },
            //        writable: false, enumerable: false, configurable: false
            //    })
            //}


            if (!XMLDocument.prototype.hasOwnProperty('render')) {
                Object.defineProperty(XMLDocument.prototype, 'render', {
                    value: async function (stylesheets) {
                        let store = this.store;
                        if (!this.documentElement) {
                            let fetched = await this.fetch();
                            if (!this.documentElement) {
                                return null;
                            }
                        }
                        let last_argument = [...arguments].pop();
                        let options = last_argument && typeof (last_argument) == 'object' && last_argument.constructor === {}.constructor && last_argument || undefined;
                        stylesheets = stylesheets !== options && stylesheets || this.stylesheets;
                        stylesheets = stylesheets instanceof Array && stylesheets || stylesheets && [stylesheets] || [];
                        let self = this;
                        let tag = store && store.tag || '';
                        if (this.selectSingleNode('xsl:*')) {//Habilitamos opción para que un documento de transformación pueda recibir un documento para transformar (Proceso inverso)
                            options = options || {};
                            options["target"] = options["target"] || document.querySelector(`[xo-store="${options["document"] && options["document"].tag || options["document"] || tag}"]`);
                            options["action"] = options["action"] || undefined
                            this.copyPropertiesFrom(options);
                            this.target = options.target
                            this.action = options.action
                            return (options["document"] || xover.xml.createDocument(`<xo:empty xmlns:xo="http://panax.io/xover"/>`).reseed()).render(this);
                        }
                        let stylesheet_target = 'body';
                        let targets = [];
                        for (let stylesheet of stylesheets.filter(stylesheet => stylesheet.role != "init" && stylesheet.role != "binding")) {
                            let xsl = stylesheet instanceof XMLDocument && stylesheet || stylesheet.document && (stylesheet.document.documentElement && stylesheet.document || await stylesheet.document.fetch()) || stylesheet.href;
                            let action = stylesheet.action;// || !stylesheet.target && "append";
                            stylesheet_target = stylesheet.target instanceof HTMLElement && stylesheet.target || document.querySelector(stylesheet.target || stylesheet_target);
                            if (!stylesheet_target) {
                                if (!(stylesheet.dependencies || {}).length) {
                                    continue;
                                }
                                let dependencies = stylesheet.dependencies.map(parent_tag => parent_tag != tag && xover.stores[parent_tag] || undefined).filter(store => store).map(store => store.render());
                                await Promise.all(dependencies);
                                stylesheet_target = stylesheet.target instanceof HTMLElement && stylesheet.target || document.querySelector(stylesheet.target || stylesheet_target);
                                if (!stylesheet_target) {
                                    console.log(`Couldn't render to ${stylesheet.target}${store.tag ? `(${store.tag})` : ''}`);
                                    return Promise.reject();
                                }
                            }
                            let data = this.cloneNode(true);
                            stylesheet_target = tag && stylesheet_target.queryChildren(`[xo-store="${tag}"][xo-stylesheet='${stylesheet.href}']`)[0] || !tag && stylesheet_target.querySelector(`[xo-stylesheet="${stylesheet.href}"]:not([xo-store])`) || stylesheet_target;
                            let target = stylesheet_target;
                            xover.site.renderingTo = target;
                            let current_cursor_style = (target.style || {}).cursor;
                            //try { current_cursor_style = 'wait' } catch (e) { console.log(e) }
                            if ((data.documentElement || data) instanceof Element) {
                                original_setAttributeNS.call((data.documentElement || data), 'http://panax.io/state/environment', "env:store", tag);
                                original_setAttributeNS.call((data.documentElement || data), 'http://panax.io/state/environment', "env:stylesheet", stylesheet.href);
                            }
                            //original_append.call(target, xover.xml.createNode(`<div xmlns="http://www.w3.org/1999/xhtml" xmlns:js="http://panax.io/xover/javascript" class="loading" onclick="this.remove()" role="alert" aria-busy="true"><div class="modal_content-loading"><div class="modal-dialog modal-dialog-centered"><div class="no-freeze-spinner"><div id="no-freeze-spinner"><div><i class="icon"><img src="assets/favicon.ico" class="ring_image" onerror="this.remove()" /></i><div></div></div></div></div></div></div></div>`));
                            data.disconnect();
                            data.target = target;
                            data.tag = '#' + xsl.href.split(/[\?#]/)[0];
                            let dom = await data.transform(xsl);
                            let documentElement = dom.firstElementChild;
                            //if (current_cursor_style) delete current_cursor_style;
                            //target.select("xhtml:div[@class='loading']").remove()
                            try { target.style.cursor = current_cursor_style } catch (e) { console.log(e) }
                            dom.querySelectorAll(`[xo-stylesheet="${stylesheet.href}"]`).forEach(el => el.removeAttribute("xo-stylesheet"));
                            let before_dom = new xover.listener.Event('beforeRender', { store: store, stylesheet: stylesheet, target: target, document: data, dom: dom }, data);
                            window.top.dispatchEvent(before_dom);
                            if (before_dom.cancelBubble || before_dom.defaultPrevented) continue;
                            if (!documentElement) {
                                //xover.dom.alert(`No result for transformation ${stylesheet.href}`)
                                continue;
                            }
                            if (dom instanceof DocumentFragment) {
                                let new_document = window.document.implementation.createDocument("http://www.w3.org/XML/1998/namespace", "", null);
                                let new_target = target.cloneNode();
                                new_document.append(new_target);
                                new_target.append(...dom.childNodes);
                                dom = new_document;
                            }

                            documentElement.setAttributeNS(null, "xo-scope", documentElement.getAttribute("xo-scope") || (data.documentElement || data).getAttribute("xo:id"));
                            documentElement.setAttributeNS(null, "xo-store", target.getAttribute("xo-store") || tag);
                            documentElement.setAttributeNS(null, "xo-stylesheet", stylesheet.href);
                            if (documentElement.id && documentElement.id == target.id || target.matches(`[xo-stylesheet="${stylesheet.href}"]:not([xo-store])`)) {
                                action = 'replace';
                            } else if (target.nodeName.toUpperCase() == documentElement.nodeName.toUpperCase() && target.getAttribute("xo-store") == documentElement.getAttribute("xo-store") && target.getAttribute("xo-stylesheet") == documentElement.getAttribute("xo-stylesheet")) {
                                action = 'replace';
                            } else if (!action && target.matches(`[xo-store="${tag}"]:not([xo-stylesheet])`)) {
                                action = 'append';
                            } else if (target.matches(`[xo-store="${tag}"][xo-stylesheet="${stylesheet.href}"]`)) {
                                action = 'replace';
                            } else if (target.matches(`[xo-store="${tag}"][xo-stylesheet]`)) {
                                continue;
                            }
                            documentElement.setAttributeNS(null, "xo-stylesheet", stylesheet.href);

                            if (action === 'replace') {
                                if (target.nodeName.toUpperCase() !== documentElement.nodeName.toUpperCase()) {
                                    let new_node = documentElement.cloneNode();
                                    target = target.replaceWith(new_node);
                                } else {
                                    let copied_attributes = documentElement.attributes.toArray();
                                    copied_attributes.filter(attr => !['class', 'xmlns'].includes(attr.nodeName)).forEach(attr => target.setAttribute(attr.name, attr.value));
                                    target.classList.forEach(class_name => target.classList.add(class_name));
                                }
                            }

                            if (target === document.body && action === 'replace') {
                                action = null;
                            }

                            if (!stylesheet.href) {
                                console.warn(`There's a missing href in a processing-instruction`)
                            }
                            //if (((dom || {}).namespaceURI || "").indexOf("http://www.mozilla.org/TransforMiix") != -1) {
                            //    // TODO: Revisar esta parte, regularmente esto sucede cuando la transformación trae más de un nodo
                            //    data.selectNodes(`processing-instruction('xml-stylesheet')`).remove();
                            //    if (!this.sources[stylesheet.href]) {
                            //        dom = data.transform(xover.sources[stylesheet.href] || xover.sources.defaults[stylesheet.href] || xover.sources.defaults["shell.xslt"]);
                            //    } else {
                            //        dom = data.transform(this.sources[stylesheet.href]);
                            //    }
                            //}
                            //if (!(dom.namespaceURI && dom.namespaceURI.indexOf("http://www.w3.org") != -1)) {
                            //    data = dom;
                            //}
                            let scripts_external, scripts;

                            let _applyScripts = function (targetDocument, scripts = []) {
                                for (let script of scripts) {
                                    if (script.selectSingleNode(`self::*[self::html:script[@src] or self::html:link[@href] or self::html:meta]`)) {
                                        if (![...targetDocument.querySelectorAll(script.tagName)].filter(node => node.isEqualNode(script.cloneNode())).length) {
                                            var new_element = targetDocument.createElement(script.tagName);
                                            [...script.attributes].map(attr => new_element.setAttributeNode(attr.cloneNode(true)));
                                            let on_load = script.textContent;

                                            if (new_element.tagName.toLowerCase() == "script") {
                                                new_element.onload = function () {
                                                    on_load && (function () { return eval.apply(this, arguments) }(on_load))
                                                };
                                            }
                                            targetDocument.head.appendChild(new_element);
                                        }
                                    } else if (!script.getAttribute("src") && script.textContent) {
                                        script.textContent = xover.string.htmlDecode(script.textContent); //Cuando el método de output es html, algunas /entidades /se pueden codificar. Si el output es xml las envía corregidas
                                        if (script.hasAttribute("defer") || script.hasAttribute("async") || script.selectSingleNode(`self::html:style`)) {
                                            if (![...targetDocument.documentElement.querySelectorAll(script.tagName)].find(node => node.isEqualNode(script))) {
                                                targetDocument.documentElement.appendChild(script);
                                            }
                                        } else {
                                            try {
                                                //function evalInScope(js, scope) {
                                                //    return function () {
                                                //        with (this) { return eval(js) }
                                                //    }.call(scope)
                                                //}
                                                //let result = evalInScope(script.textContent, script.getAttributeNode("xo-scope") && script.scope || window)
                                                let result = (function () {
                                                    xover.context = script;
                                                    return eval.apply(this, arguments)
                                                }(`/*${stylesheet.href}*/ let self = xover.context; let context = self.parentNode; ${script.textContent};xover.context = undefined;`));
                                                if (['string', 'number', 'boolean', 'date'].includes(typeof (result))) {
                                                    let target = document.getElementById(script.id);
                                                    target && target.parentNode.replaceChild(target.ownerDocument.createTextNode(result), target);
                                                }
                                            } catch (message) {
                                                console.error(message)
                                            }
                                        }
                                    } else {
                                        throw (new Error(`A script couldn't be loaded.`));
                                    }
                                }
                            }
                            //let styles = document.head.appendChild(await xover.sources.load("styles.css"));
                            let header_tags = xover.xml.createNode(`<header xmlns="http://www.w3.org/1999/xhtml"/>`)
                            scripts_external = dom.selectNodes('//*[self::html:script[@src or @async or not(text())][not(@defer)] or self::html:link[@href] or self::html:meta][not(text())]');
                            scripts_external.forEach(script => header_tags.append(script));

                            _applyScripts(document, scripts_external);
                            dom.selectNodes('//@xo-attribute[.="" or .="xo:id"]').forEach(el => el.parentNode.removeAttributeNode(el))
                            if (!target) {
                                if (xover.debug.enabled) {
                                    if (stylesheet_target) {
                                        throw (new Error(`No existe la ubicación "${stylesheet_target}"`));
                                    }
                                }
                                let missing_stores = []
                                let active_tags = xover.site.activeTags();
                                active_tags.filter(_tag => tag != _tag && xover.stores[_tag] && !xover.stores[_tag].isRendered).map(async _tag => {
                                    let store = xover.stores[_tag];
                                    if (store) {
                                        missing_stores.push(store.render(/*true*/));
                                    }
                                });
                                await Promise.all(missing_stores);
                                self.render();
                                //self.isActive = false;
                                continue;
                            }
                            target.disconnected = false;
                            dom.tag = '#' + xsl.href.split(/[\?#]/)[0];
                            let render_event = new xover.listener.Event('render', { store, stylesheet, target, dom, context: data }, dom);
                            window.top.dispatchEvent(render_event);
                            if (render_event.cancelBubble || render_event.defaultPrevented) continue;
                            if (documentElement && (documentElement.tagName || '').toLowerCase() == "html") {
                                //dom.namespaceURI == "http://www.w3.org/1999/xhtml"
                                //target = document.body;
                                xover.dom.setEncryption(dom, 'UTF-7');
                                dom.select('//text()[.="�"]').remove();
                                let iframe;
                                if (document.activeElement.tagName.toLowerCase() == 'iframe') {
                                    iframe = document.activeElement;
                                    target = (document.activeElement || {}).contentDocument.querySelector('main,table,div,span');
                                    target.parentElement.replaceChild(dom.querySelector(target.tagName.toLowerCase()), target);
                                    //if ((dom || dom).selectNodes) { //(dom instanceof XMLDocument) {
                                    //    _applyScripts((document.activeElement || {}).contentDocument, dom);
                                    //}
                                } else {
                                    target.replaceChildren();
                                    if (target.tagName.toLowerCase() == "iframe") {
                                        iframe = target;
                                    } else {
                                        iframe = document.createElement('iframe');
                                        //iframe.width = "100%"
                                        //iframe.height = "1000"
                                        iframe.setAttributeNS(null, "xo-store", tag);
                                        iframe.setAttributeNS(null, "xo-stylesheet", stylesheet.href);
                                        iframe.style.backgroundColor = 'white';
                                        iframe = target.appendChild(iframe);
                                        Object.entries(xover.listener).map(([event_name, handler]) => iframe.addEventListener(event_name, handler));
                                        //iframe.addEventListener('focusout', xover.listeners.dom.onfocusout);
                                        //iframe.addEventListener('change', xover.listeners.dom.onchange);
                                    }
                                    var url = xover.dom.getGeneratedPageURL({
                                        html: xover.string.htmlDecode(dom.toString()),
                                        css: (dom.querySelector('style') || {}).innerHTML,
                                        js: `var xover = (xover || parent.xover); document.xover_global_refresh_disabled=true; let iframe=parent.document.querySelector('iframe'); iframe.height=document.querySelector('body').scrollHeight+10; iframe.width=document.querySelector('body').scrollWidth+10; xover.modernize(iframe.contentWindow); document.querySelector('body').setAttributeNS(null, "xo-store", '${tag}');` //+ js//((dom.querySelector('script') || {}).innerHTML || "")
                                        //window.top.document.querySelector('body').setAttributeNS(null, "xo-store", window.top.location.hash)
                                    });
                                    iframe.src = url;
                                }
                                target = iframe;
                                xover.site.restore(target);
                                //} else if (!(dom.namespaceURI && dom.namespaceURI.indexOf("http://www.w3.org") != -1)) {
                                //    dom = await dom.transform('error.xslt');
                                //    target = document.querySelector('main') || document.querySelector('body')
                                //    if (stylesheet.action == "replace") {
                                //        target = target.replaceWith(dom);
                                //    } else {
                                //        xover.dom.clear(target);
                                //        target.append(...dom.parentElement.childNodes);
                                //    }
                            } else {
                                let post_render_scripts = dom.selectNodes('//*[self::html:script][@src]');
                                post_render_scripts.forEach(script => header_tags.append(script));

                                scripts = dom.selectNodes('//*[self::html:script][not(@src)][text()]').map(el => {
                                    !el.getAttribute("id") && el.setAttribute("id", xover.cryptography.generateUUID())
                                    let cloned = el.cloneNode(true);
                                    el.textContent = ''
                                    Object.defineProperty(cloned, 'parentNode', {
                                        value: el.parentNode
                                    });
                                    return cloned;
                                });
                                let active_element = document.activeElement;
                                let active_element_selector = active_element.selector;
                                if (action == "replace") {
                                    target.replaceChildren(...documentElement.childNodes)
                                    //target = target.replaceWith(documentElement);//target = [target.replace(dom)];
                                    //let to_be_replaced = target.querySelector(active_element_selector)
                                    //to_be_replaced && to_be_replaced.replaceWith(active_element)
                                } else {//if (action == "append") {
                                    //target.append(dom);
                                    //} else {
                                    //    xover.dom.clear(target);
                                    //target.append(...dom.cloneNode(true).childNodes);
                                    let inserted_nodes = target.append(...dom.childNodes);
                                    target = inserted_nodes.find(node => node.nodeType == 1)
                                }
                                target.document = this;
                                target.context = data;
                                _applyScripts(document, post_render_scripts);
                                //if (action == "replace") {
                                //    target = target.replaceWith(dom)//target = [target.replace(dom)];
                                //    //let to_be_replaced = target.querySelector(active_element_selector)
                                //    //to_be_replaced && to_be_replaced.replaceWith(active_element)
                                //    target.document = data;
                                //} else {//if (action == "append") {
                                //    //target.append(dom);
                                //    //} else {
                                //    //    xover.dom.clear(target);
                                //    //target.append(...dom.cloneNode(true).childNodes);
                                //    dom.childNodes.filter(el => el instanceof Element).forEach(el => el.document = data)
                                //    target.append(...dom.parentNode.childNodes);
                                //}

                                var lines = dom.querySelectorAll(".leader-line")
                                for (let l = 0; l < lines.length; ++l) {
                                    lines[l].remove();
                                }
                                if (dom.selectNodes) {
                                    _applyScripts(document, dom.selectNodes('//*[self::html:script][text()]'));
                                }
                                xover.site.restore(target);
                            }
                            window.top.dispatchEvent(new xover.listener.Event('render', { store: store, stylesheet: stylesheet, target: target, dom: target }, self));

                            targets.push(target);

                            if (window.MathJax) {
                                MathJax.typeset && MathJax.typeset();
                            } else if (target.selectSingleNode('//mml:math') || ((target || {}).textContent || '').match(/(?:\$\$|\\\(|\\\[|\\begin\{.*?})/)) { //soporte para MathML
                                if (!window.MathJax) {
                                    window.MathJax = {
                                        loader: { load: ['[mml]/mml3'] }
                                    }
                                }
                                let script = document.createElement('script');
                                script.src = 'https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-chtml.js';
                                document.head.appendChild(script);
                            }

                            let unbound_elements = target.querySelectorAll('[xo-source=""],[xo-scope=""],[xo-attribute=""]');
                            if (unbound_elements.length) {
                                console.warn(`There ${unbound_elements.length > 1 ? 'are' : 'is'} ${unbound_elements.length} disconnected element${unbound_elements.length > 1 ? 's' : ''}`, unbound_elements)
                            }

                            _applyScripts(document, scripts);
                            xover.evaluateParams(target);
                            target.querySelectorAll('[xo-stylesheet]:not([xo-store])').forEach(el => data.render(
                                data.createProcessingInstruction('xml-stylesheet', { type: 'text/xsl', href: el.getAttribute("xo-stylesheet"), target: el.selector, action: "replace" })
                            ));
                            target.querySelectorAll('[xo-scope="inherit"]').forEach(el => el.removeAttribute("xo-scope"));
                            xover.initializeElementListeners(target);

                            /*TODO: Mover este código a algún script diferido*/
                            target.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (tooltipTriggerEl) {
                                return new bootstrap.Tooltip(tooltipTriggerEl)
                            })
                            dependants = [...target.querySelectorAll('*[xo-store],*[xo-stylesheet]')];
                            //window.top.dispatchEvent(new xover.listener.Event('render', { store: store, stylesheet: stylesheet, target: target }, store));
                            dependants.forEach(el => el.render());
                            delete xover.site.renderingTo;
                        }
                        return Promise.resolve(targets);
                    },
                    writable: false, enumerable: false, configurable: false
                });
            }

            var appendChild_original = Element.prototype.appendChild
            //Element.prototype.appendChild = function (new_node, refresh) {
            //    if (!(new_node instanceof Node)) throw (new Error("Element to be added is not a valid Node"));
            //    let self = (this.ownerDocument && this.ownerDocument.store && this.ownerDocument.store.find(this) || this);
            //    if (!(self.ownerDocument instanceof XMLDocument)) {
            //        return appendChild_original.apply(self, [...arguments]);
            //    }
            //    refresh = Array.prototype.coalesce(refresh, true);
            //    if (refresh && new_node && self.ownerDocument.store /*self.ownerDocument.documentElement.selectSingleNode('//@xo:id')*/) {
            //        new_node = new_node.reseed();
            //        var refresh = Array.prototype.coalesce(refresh, true);
            //        appendChild_original.apply(self, [new_node]);
            //        self.ownerDocument.store.render(refresh);
            //    } else {
            //        return appendChild_original.apply(self, arguments);
            //    }
            //    window.top.dispatchEvent(new xover.listener.Event('change', { node: new_node }, new_node));
            //}

            Date.prototype.toISOString = function () {/*Current method ignores z-time offset*/
                var tzo = -this.getTimezoneOffset(),
                    dif = tzo >= 0 ? '+' : '-',
                    pad = function (num) {
                        var norm = Math.floor(Math.abs(num));
                        return (norm < 10 ? '0' : '') + norm;
                    };

                return this.getFullYear() +
                    '-' + pad(this.getMonth() + 1) +
                    '-' + pad(this.getDate()) +
                    'T' + pad(this.getHours()) +
                    ':' + pad(this.getMinutes()) +
                    ':' + pad(this.getSeconds()) +
                    '.' + pad(this.getMilliseconds()) +
                    'Z';
            }

            Date.prototype.toLongDateString = function (format = 'es-mx') {
                let date = this;
                const monthNames = {
                    "es-mx": ["Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio",
                        "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"
                    ]
                };
                if (date instanceof Date) {
                    date = date.toISOString()
                }
                var parts = date.match(/(\d{4})(\/|-)(\d{1,2})\2(\d{1,2})/)
                if (format.indexOf('es') === 0) {
                    return parts[4] + ' de ' + monthNames[format][parseInt(parts[3]) - 1] + ' de ' + parts[1];
                }
            }
        }

        // Production steps of ECMA-262, Edition 5, 15.4.4.18
        // Reference: http://es5.github.com/#x15.4.4.18
        if (!Array.prototype.forEach) {
            Array.prototype.forEach = function forEach(callback, thisArg) {
                'use strict';
                var T, k;

                if (this == null) {
                    throw new TypeError("this is null or not defined");
                }

                var kValue,
                    // 1. Let O be the result of calling ToObject passing the |this| value as the argument.
                    O = Object(this),

                    // 2. Let lenValue be the result of calling the Get internal method of O with the argument "length".
                    // 3. Let len be ToUint32(lenValue).
                    len = O.length >>> 0; // Hack to convert O.length to a UInt32

                // 4. If IsCallable(callback) is false, throw a TypeError exception.
                // See: http://es5.github.com/#x9.11
                if ({}.toString.call(callback) !== "[object Function]") {
                    throw new TypeError(callback + " is not a function");
                }

                // 5. If thisArg was supplied, let T be thisArg; else let T be undefined.
                if (arguments.length >= 2) {
                    T = thisArg;
                }

                // 6. Let k be 0
                k = 0;

                // 7. Repeat, while k < len
                while (k < len) {

                    // a. Let Pk be ToString(k).
                    //   This is implicit for LHS operands of the in operator
                    // b. Let kPresent be the result of calling the HasProperty internal method of O with argument Pk.
                    //   This step can be combined with c
                    // c. If kPresent is true, then
                    if (k in O) {

                        // i. Let kValue be the result of calling the Get internal method of O with argument Pk.
                        kValue = O[k];

                        // ii. Call the Call internal method of callback with T as the this value and
                        // argument list containing kValue, k, and O.
                        callback.call(T, kValue, k, O);
                    }
                    // d. Increase k by 1.
                    k++;
                }
                // 8. return undefined
            };
        }
        targetWindow.modernized = true;
    }
    console.info("Powered by XOVER")
}

//xover.listener.on('mouseup::textarea', function () {
//    let el = event.srcElement;
//    let scope = el.scope;
//    if (!scope) return;
//    if (scope instanceof Attr) {
//        scope.parentNode.set(`height:${scope.localName}`, el.offsetHeight, { silent: true });
//        scope.parentNode.set(`width:${scope.localName}`, el.offsetWidth, { silent: true });
//    } else {
//        scope.set('state:height', el.offsetHeight, { silent: true });
//        scope.set('state:width', el.offsetWidth, { silent: true });
//    }
//});

xover.listener.on(['change::*[xo-attribute]'], function () {
    if (this.type === 'date' && this.value != '' && !isValidISODate(this.value) || this.preventChangeEvent) {
        this.preventChangeEvent = undefined;
        event.preventDefault();
        return;
    }
    let srcElement = this;
    let scope = this.scope;
    if (!scope) return;
    let _attribute = scope instanceof Attr && scope.name || scope instanceof Text && 'text()' || undefined;
    let value = (srcElement instanceof HTMLInputElement && ['checkbox', 'radiogroup'].includes(srcElement.type)) ? srcElement.checked && srcElement.value || null : srcElement.value;
    //if (srcElement.defaultPrevented) {

    //}
    if (scope instanceof Attr || scope instanceof Text) {
        scope.set(value);
    } else if (scope instanceof Node) {
        _attribute && scope.set(_attribute, value);
    }
})

//xover.listener.on(['change::input[type="file"]'], async function () {
//    let srcElement = this;
//    if (!(srcElement.files && srcElement.files[0])) return;
//    let store = await xover.storehouse.files;
//    let scope = this.scope;
//    if (!scope) return;
//    let _attribute = scope instanceof Attr && scope.name || scope instanceof Text && 'text()' || undefined;
//    store.add(srcElement.files).forEach(record => {
//        [...srcElement.ownerDocument.querySelectorAll(`*[for="${srcElement.id}"] img`)].forEach(img => img.src = record.uid);
//        if (scope instanceof Text || _attribute === 'text') {
//            scope.set(record.uid);
//        } else if (scope instanceof Attr || _attribute) {
//            let { prefix, name: attribute_name } = xover.xml.getAttributeParts(_attribute);
//            scope = scope instanceof Attr ? scope.ownerElement : scope;
//            let metadata = Object.assign({}, xover.string.getFileParts(record.saveAs), record, { name: record.file["name"], type: record.file["type"] });
//            delete metadata["file"];
//            scope.set(_attribute, record.uid);
//            //scope.set(`metadata:${attribute_name}`, metadata);
//            if (metadata.name) {
//                scope.set(`text:${attribute_name}`, metadata.name);
//            }
//        }
//    })
//})

xover.dom.fileManager = async function (files) {
    if (!(files[0])) return [];
    let database = await xover.storehouse.files;
    let cached_files = database.add(files);
    let file_value = cached_files.map(record => {
        let metadata = Object.assign({}, xover.string.getFileParts(record.saveAs), record, { name: record.file["name"], type: record.file["type"] });
        return `${record.uid}?name=${metadata.name}`
    });
    return file_value;
}

xover.listener.on(['change::input[type="file"]'], async function () {
    let srcElement = this;
    let scope = this.scope;
    if (!scope) return;
    let file_string = await xover.dom.fileManager(srcElement.files);
    scope.set(file_string.join(";"));
})

xover.modernize();

xover.dom.toExcel = (function (table, name) {
    if (!table.nodeType) table = document.getElementById(table);
    table = table.cloneNode(true);
    [...table.querySelectorAll('.non_printable,input,select,textarea')].forEach(el => el.remove());
    var myBlob = new Blob(["\ufeff" + table.outerHTML], { type: 'application/vnd.ms-excel;charset=utf-8' });
    var url = window.URL.createObjectURL(myBlob);
    var a = document.createElement("a");
    document.body.appendChild(a);
    a.href = url;
    a.download = name.replace(/^[^\d\w]/, '');
    a.click();
    setTimeout(function () { window.URL.revokeObjectURL(url); }, 0);
});

//document.addEventListener('mousedown', function (event) {
//    if (event.shiftKey) {
//        event.preventDefault();
//    }
//});

xover.listener.on('Response:reject', function ({ response, request }) {
    if (!response.ok && ((request.url || {}).pathname || '').indexOf(`.manifest`) != -1) {
        event.preventDefault();
    }
})

xover.listener.on(['unhandledrejection', 'error'], async (event) => {
    if (event.defaultPrevented || event.cancelBubble) {
        return;
    }
    if (xover.init.status != 'initialized') {
        await xover.init();
    }
    try {
        let reason = event.message || event.reason;
        if (!reason) return;
        if (!(typeof (reason) == 'string' || reason instanceof Error)) {
            let unhandledrejection_event = new xover.listener.Event(`reject`, {}, reason);
            window.top.dispatchEvent(unhandledrejection_event);
            if (unhandledrejection_event.defaultPrevented) return;
        }
        if (reason instanceof TypeError || reason instanceof DOMException) {
            String(reason).alert()
            console.error(reason.stack || reason)
        } else if (reason instanceof HTMLElement) {
            xover.dom.alert(reason);
        } else if (typeof (reason.render) != 'undefined') {
            reason.render();
        } else {
            String(reason).alert()
        }
    } catch (e) {
        console.error(e);
    }
});