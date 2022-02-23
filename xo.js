﻿var xdom = {};
xdom.app = {};
xdom.debug = {};
xdom.browser = {};
xdom.cache = {};
xdom.cryptography = {};
xdom.cryptography.generateUUID = function () {//from https://stackoverflow.com/questions/105034/how-to-create-a-guid-uuid
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
xdom.cryptography.decodeJwt = function (token) {//from https://stackoverflow.com/questions/38552003/how-to-decode-jwt-token-in-javascript-without-using-a-library
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
}
xdom.cryptography.encodeBase64 = function (str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function (match, p1) {
        return String.fromCharCode('0x' + p1);
    }));
}
xdom.cryptography.encodeMD5 = function (str) {
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
        nblk = ((str.length + 8) >> 6) + 1;
        blks = new Array(nblk * 16);
        for (let i = 0; i < nblk * 16; i++) blks[i] = 0;
        for (let i = 0; i < str.length; i++)
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

xdom.custom = {};
xdom.data = {};
xdom.stores = new Proxy({}, {
    get: function (self, key) {
        if (key in self) {
            return self[key];
        } else if (key[0] == '$') {
            return xdom.stores[`#${key.split("$").pop()}`];
        } else if (key[0] == '#' && xdom.session[key]) {
            restored_document = xdom.session[key];
            if (!(restored_document instanceof xdom.Store) && restored_document instanceof XMLDocument) {
                self[key] = new xdom.Store(restored_document, { tag: key });
            }
            return self[key];
        } else if (key[0] == '#' && key in xdom.sources) {
            return xdom.sources[key];
        } else if (key[0] == '#' && xdom.stores.defaults[key]) {
            let _store = xdom.stores.defaults[key] && new xdom.Store(xdom.stores.defaults[key], { tag: key });
            if (_store) {
                self[key] = _store;
            }
            return self[key];
        } else if (key !== key.toLowerCase()) {
            return xdom.stores[key.toLowerCase()];
            //} else if (String(key) != "undefined") {
            //    if (key.match("^#")) {
            //        throw (`Store "${key}" doesn't exist in stores.`)
            //    } else {
            //        throw (`Key or method "${key}" doesn't exist in stores.`)
            //    }
        } else {
            return;
        }
    },
    set: function (self, key, value) {
        let refresh;
        if (value && !(value instanceof xdom.Store)) {
            if (value instanceof XMLDocument && value.stylesheets.length) {
                value = new xdom.Store(value);
            } else {
                throw ('Supplied store is not valid type');
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
        let same = self[xdom.state.seed] === self[key]
        sessionStorage.removeItem(key);
        if (exists) {
            Reflect.deleteProperty(self, key);
            if (same && xdom.state.position > 1) {
                history.back();
            } else {
                xdom.dom.refresh();
            }
        }
        return exists && !(key in self)
    }, has: function (self, key) {
        return key in self || key.toLowerCase() in self || key in xdom.session || key in ((xdom.manifest.server || {}).endpoints || {});
    }
});

Object.defineProperty(xdom.stores, 'defaults', {
    value: {},
    writable: false, enumerable: false, configurable: false
});

xdom.data.binding = {};
xdom.data.binding["max_subscribers"] = 30;
xdom.data.binding.sources = {};
xdom.data.binding.requests = {};
xdom.data.titles = {};
xdom.database = new Proxy({
    config: {
        'files': { keyPath: "uid" }
        , 'stores': { autoIncrement: true }
    }
}, {
    get: function (self, key) {
        if (key in self) {
            return self[key];
        }
        return self.open(key);
    }
});

Object.defineProperty(xdom.database, 'files', {
    get: async function () {
        let store = await xdom.database.open('files', { keyPath: "uid" });
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
                record.saveAs = `${record.id}.${record.extension}`;
                record.file = file;
                _add(record);
                _cached_ids.push(record);
            }
            return _cached_ids;
        }
        return store;
    }
});


Object.defineProperty(xdom.database, 'stores', {
    get: async function () {
        let store = await xdom.database.open('stores');
        let _add = store.add;
        store.add = function (store, tag = store.tag) {
            _add(new File([store.document], store.tag, {
                type: "application/xml",
            }), tag);
        }
        let _put = store.put;
        store.put = function (store, tag = store.tag) {
            _put(new File([store.document], store.tag, {
                type: "application/xml",
            }), tag);
        }
        let _get = store.get;
        store.get = async function (store_id) {
            let document = await _get(store_id);
            return xdom.xml.createDocument(await document.text());
        }
        return store;
    }
});

Object.defineProperties(xdom.database, {
    open: {
        value: function (key, config = { autoIncrement: true }) {
            return new Promise(async (resolve, reject) => {
                let stores = Object.fromEntries(Object.entries(Object.getOwnPropertyDescriptors(xdom.database)).filter(([prop, func]) => func["get"] || func["enumerable"]));
                //let database = await indexedDB.databases().then(databases => databases.find(db => db.name == 'xdom.database'));
                let connection = indexedDB.open('xdom.database', Object.keys(stores).length);
                let handler = function (event) {
                    let store = event.target.result.transaction([key], 'readwrite').objectStore(key);
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

                            request.onsuccess = function (event) {
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
                            db.createObjectStore(store_name, xdom.database.config[store_name]);//autoIncrement: true
                        }
                    });
                };
            })
        }
    }
})

xdom.dom = {};
xdom.dom.history = [];
xdom.dom.intervals = new Proxy({}, {
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

xdom.dom.controls = {};
xdom.dom.refreshTitle = function (input) {
    let document_title = (input || document.title).match(/([^\(]+)(.*)/);
    let [, title, environment] = (document_title || [, "", ""]);
    document.title = title.replace(/\s+$/, '') + (` (${xdom.session.database_id && xdom.session.database_id != 'main' ? xdom.session.database_id : 'v.'} ${xdom.session.cache_name && xdom.session.cache_name.split('_').pop() || ""})`).replace(/\((v\.)?\s+\)|\s+(?=\))/g, '');
}
xdom.json = {};

xdom.listener = {};
xdom.listener.Event = function (event_name, params) {
    if (!(this instanceof xdom.listener.Event)) return new xdom.listener.Event(event_name, params);
    let _event = new CustomEvent(event_name, { detail: params, cancelable: true });
    //Object.setPrototypeOf(_event, CustomEvent.prototype);
    //Object.setPrototypeOf(_event, xdom.listener.Event.prototype);
    return _event;
}
xdom.listener.Event.prototype = Object.create(CustomEvent.prototype);

Object.defineProperty(xdom.listener, 'dispatcher', {
    value: async function (event) {
        if (xdom.init.status != 'initialized') {
            await xdom.init();
        }
        /*Los listeners se adjuntan y ejecutan en el orden en que fueron creados. Con este método se ejecutan en orden inverso y pueden detener la propagación para quitar el comportamiento de ejecución natural. Se tienen que agregar con el método */
        Object.values(xdom.listener[event.type]).slice(0).reverse().map((handler) => !event.cancelBubble && handler.apply(event.target, event instanceof CustomEvent && (event.detail instanceof Array && [...event.detail, event] || event.detail && [event.detail, event] || [event]) || arguments));
    },
    writable: true, enumerable: false, configurable: false
});

Object.defineProperty(xdom.listener, 'on', {
    value: function (name__or_list, handler) {
        name__or_list = name__or_list instanceof Array && name__or_list || [name__or_list];
        name__or_list.map(event_name => {
            xdom.listener[event_name] = (xdom.listener[event_name] || []);
            xdom.listener[event_name][handler.toString()] = handler;
            window.top.removeEventListener(event_name, xdom.listener.dispatcher);
            window.top.addEventListener(event_name, xdom.listener.dispatcher);
        })
    },
    writable: true, enumerable: false, configurable: false
});

xdom.listener.on('keyup', async function (event) {
    if (event.defaultPrevented) { return; }
    if (event.keyCode == 27) {
        xdom.data.removeMessage(document.querySelector("[role='alertdialog']"));
    }
})

xdom.listener.on('error', async function ({ event }) {
    if (!(event && !(event.defaultPrevented))) return;
    let srcElement = event.target;
    let store = await xdom.database.files;
    let record = await store.get(srcElement.src);
    if (record) {
        let old_url = srcElement.src;
        if (record.file.type.indexOf('image') !== -1) {
            let new_url = window.URL.createObjectURL(record.file);
            srcElement.src = new_url;
            record.uid = new_url;
            store.put(record);
            srcElement.source.selectNodes(`.//@*[.='${old_url}']`).forEach(node => node.value = new_url);
            store.delete(old_url);
        } else {
            if ([...document.querySelectorAll('script[src]')].find(node => node.getAttribute("src").indexOf('bootstrap') !== -1)) { //
                let new_element = targetDocument.createElement("i");
                new_element.className = `bi bi-filetype bi-filetype-${record.extension}`;
                if (srcElement.closest('picture')) {
                    srcElement.closest('picture').replace(new_element);
                } else {
                    srcElement.replace(new_element);
                }
            }
        }
    } /*else {
        srcElement.src = ''
    }*/
})

xdom.listener.on('popstate', async function (event) {
    if (event.defaultPrevented) return;
    if (this.popping) {
        this.popping().cancel();
        //let current_hash = xdom.data.hashTagName();
        //history.replaceState({
        //    hash: current_hash
        //    , prev: ((history.state || {}).prev || [])
        //}, event.target.textContent, current_hash);
        this.popping = undefined;
    }
    function popstate() {
        let finished = false;
        let cancel = () => finished = true;
        xdom.session.database_id = xdom.session.database_id;
        const promise = new Promise((resolve, reject) => {
            setTimeout(async () => {
                let hashtag = (xdom.state.seed || '#')
                if (xdom.stores[hashtag]) {
                    let store = xdom.stores[hashtag];
                    await store.render(xdom.state.active == xdom.state.seed || xdom.state.active == store.tag);
                    if (store instanceof xdom.Store && !store.isRendered) {
                        xdom.stores.active = store;
                    }
                    console.log("Navigated to " + hashtag);
                } else {
                    // TODO: Revisar esta sección. Puede estar desactualizada.
                    //let current_hash = xdom.stores.seed.tag;
                    //history.replaceState({
                    //    hash: current_hash
                    //    , prev: ((history.state || {}).prev || [])
                    //}, ((event || {}).target || {}).textContent, current_hash);
                }
                resolve();
            }, 500);
            cancel = () => {
                if (finished) {
                    return;
                }
                reject();
            };

            if (finished) {
                cancel();
            }
        }).then((resolvedValue) => {
            this.popping = undefined;
            finished = true;
            return resolvedValue;
        }).catch((err) => {
            finished = true;
            return err;
        });
        return { promise, cancel }
    }
    this.popping = popstate;
    this.popping();
})

xdom.listener.on(['pageshow', 'popstate'], async function (event) {
    if (event.defaultPrevented) return;
    const positionLastShown = Number(sessionStorage.getItem('lastPosition'));
    if (history.state) delete history.state.active;
    if (!history.state && !location.hash && positionLastShown || xdom.state.position > 1 && (!((location.hash || "#") in xdom.stores) || !xdom.stores[xdom.state.seed])) {
        history.back();
        event.stopPropagation()
    } else if (history.state && positionLastShown > xdom.state.position) {
        window.top.dispatchEvent(new CustomEvent('navigatedBack', { bubbles: false }));
    } else if (history.state && positionLastShown < xdom.state.position) {
        window.top.dispatchEvent(new CustomEvent('navigatedForward', { bubbles: false }));
    }
})

xdom.listener.on('submitSuccess', async function (event) {
    if (event.defaultPrevented) return;
    console.log("from xdom " + xdom.listener['submitSuccess'].length)
})

xdom.listener.on('navigatedForward', function (event) {
    if (event.defaultPrevented) return;
    if (xdom.state.seed == "#" && xdom.state.position > 1 && !(xdom.state.prev || []).length) {
        alert("Navigated forward");
        history.back();
    }
})

xdom.listener.keypress = {};
xdom.mimeTypes = {};
xdom.mimeTypes["js"] = "application/javascript"
xdom.mimeTypes["json"] = "application/json"
xdom.mimeTypes["xml"] = "text/xml"
xdom.mimeTypes["xsl"] = "text/xsl"
xdom.mimeTypes["xslt"] = "text/xsl"
xdom.manifest = {};
xdom.messages = {};
xdom.server = new Proxy({}, {
    get: function (self, key) {
        let handler = (async (parameters = {}, options = {}, payload) => {
            if (!(xdom.manifest.server && xdom.manifest.server.endpoints && xdom.manifest.server.endpoints[key])) {
                throw (`Endpoint "${key}" not configured`);
            }
            var url, params, payload;
            let return_value, request, response;
            params = new URLSearchParams(parameters);
            url = new URL(xdom.manifest.server["endpoints"][key], location.origin + location.pathname.replace(/[^/]+$/, ""));
            [...params.entries()].map(([key, value]) => url.searchParams.set(key, value));

            let headers = new Headers(options["headers"]);
            //headers.set("Accept", (headers.get("Accept") || "text/xml"))
            headers.set("X-Debugging", (headers.get("X-Debugging") || xdom.debug.enabled));
            headers.set("X-Rebuild", (headers.get("X-Rebuild") || (xdom.listener.keypress.altKey ? true : false)));
            options["headers"] = headers;
            try {
                [return_value, request, response] = await xdom.fetch(url, options, payload).then(response => [response.body, response.request, response.originalResponse]);
            } catch (e) {
                [return_value, request, response] = [e.body, e.request, e.originalResponse]
            }
            return_value instanceof XMLDocument && options["stylesheets"] && options["stylesheets"].reverse().map(stylesheet => {
                return_value.addStylesheet(stylesheet);
            });

            if (options["auto-process"] !== false) {
                if (return_value instanceof XMLDocument && (return_value.stylesheets || []).length) {
                    return_value = new xdom.Store(return_value, { tag: options["tag"], initiator: request.initiator });
                    return_value.render(/*true*/);
                    if (!return_value.isRendered) {
                        xdom.stores.active = return_value;
                    }
                } else if (return_value instanceof DocumentFragment) {
                    xdom.dom.createDialog(return_value);
                }
            }
            return new Promise((resolve, reject) => {
                if (response.status >= 200 && response.status < 300) {
                    resolve(return_value);
                } else {
                    reject(return_value);
                }
            });
        })

        if (self.hasOwnProperty(key)/* && xdom.manifest.server && xdom.manifest.server.endpoints && xdom.manifest.server.endpoints[key]*/) {
            Object.defineProperty(self[key], 'call', {
                value: function () {
                    return handler.apply(arguments[0], [...arguments].splice(1));
                },
                writable: true, enumerable: false, configurable: false
            });
            return self[key];
        } else if (!(xdom.manifest.server && xdom.manifest.server.endpoints && xdom.manifest.server.endpoints[key])) {
            throw (`Endpoint "${key}" not configured`);
        } else {
            return handler;
        }
    }, has: function (self, key) {
        return key in self || key in ((xdom.manifest.server || {}).endpoints || {});
    }
})

xdom.session = new Proxy({}, {
    get: function (self, key) {
        let item;
        if (key in self) {
            item = self[key];
        } else {
            item = xdom.session.getKey(key);
        }
        if (item instanceof Array) {
            for (let prop of ['pop', 'push', 'splice', 'shift', 'unshift', 'remove', 'removeAll']) {
                Object.defineProperty(item, prop, {
                    value: function () {
                        let result = Array.prototype[prop].apply(item, arguments);
                        xdom.session[key] = item;
                        return result;
                    }, writable: true, enumerable: true, configurable: false
                })

            }

        }
        return item;
    },
    set: function (self, key, new_value) {
        let refresh;
        let old_value = xdom.session.getKey(key);
        if (new_value instanceof Array) {
            refresh = !old_value && !!new_value || old_value.length === new_value.length && old_value.every((value, index) => value === new_value[index]);
        } else {
            refresh = old_value !== new_value;
        }
        xdom.session.setKey(key, new_value);
        if (refresh) {
            let render_promises = [];
            var key = key, new_value = new_value;
            window.top.dispatchEvent(new xdom.listener.Event('sessionChanged', { attribute: key, new: new_value, old: old_value }));
            if (["status"].includes(key)) {
                xdom.stores.active.render();
            }
            let active_stores = xdom.stores.getActive();
            let promises = [];
            [...Object.values(active_stores), ...Object.values(active_stores.getInitiators())].map(store => promises.push(store.library.load()));
            self[key] = new Promise((resolve, reject) => {
                Promise.all(promises).then(() => {
                    [...Object.values(active_stores), ...Object.values(active_stores.getInitiators())].filter(store => {
                        let stylesheets = store.stylesheets.getDocuments();
                        Promise.all(stylesheets).then(() => {
                            if (["status"].includes(key) || stylesheets.find(stylesheet => {
                                return !!(stylesheet || window.document.createElement('p')).selectSingleNode(`//xsl:stylesheet/xsl:param[@name='session:${key}']`)
                            })) {
                                console.log(`Rendering ${store.tag} triggered by ${key}`);
                                if (xdom.stores.active.initiator == store) {
                                    xdom.stores.active = store
                                } else if (store.initiator) {
                                    xdom.stores.active = store.initiator;
                                } else {
                                    render_promises.push(store.render());
                                }
                            }
                            Promise.all(render_promises).then(() => {
                                resolve(new_value);
                            }).catch(() => {
                                resolve(old_value);
                            });
                        }).then(() => {
                            if (!stylesheets.length) {
                                resolve(new_value);
                            }
                        }).catch(() => {
                            resolve(old_value);
                        });
                    })
                }).then(() => {
                    if (!promises.length) {
                        resolve(new_value);
                    }
                }).catch(() => {
                    resolve(old_value);
                });
            }).then((result) => {
                self[key] = result
                return result;
            });
        }
        if (xdom.session.id) {
            xdom.storage.setKey(key, new_value);
            xdom.storage.setKey(key, undefined);
        }
        return self[key];
    },
    deleteProperty: function (self, key) {
        xdom.session[key] = undefined;
    },
    has: function (self, key) {
        return key in self || key in sessionStorage
    }
})

Object.defineProperty(xdom.session, 'getKey', {
    value: function (key) {
        if (typeof (Storage) !== "undefined") {
            var value = JSON.parse(sessionStorage.getItem(key));
            if (!(key in sessionStorage)) {
                return undefined;
            } else if (value == "null" || value == "undefined") { //Para guardar específicamente null o undefined, se guardarían como texto plano;
                return eval(value);
            } else if (value && key.indexOf("#") != -1) {
                return (xdom.xml.createDocument(value, false) || value);
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

Object.defineProperty(xdom.session, 'setKey', {
    value: function (key, value) {
        if (typeof (Storage) !== "undefined") {
            if (value instanceof Promise) {
                return false;
            } else if (value === undefined) {
                sessionStorage.removeItem(key);
            } else if ((value instanceof Node || value instanceof xdom.Store) && value.toString) {
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

Object.defineProperty(xdom.session, 'getCurrentStatus', {
    value: async function () {
        return xdom.session.checkStatus();
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.session, 'checkStatus', {
    value: async function (settings) {
        if (!(navigator.onLine || 'status' in xdom.server)) return xdom.session.status;
        let server_status = {};
        //if (!(((xdom.manifest.server || {}).endpoints || {}).session)) {
        //    return Promise.reject(new Error("Session endpoint not configured."));
        //}
        if ('status' in xdom.server) {
            try {
                server_status = await xdom.server.status();
            } catch (e) {
                server_status = { "status": "unauthorized" }
            }
        }
        return new Promise((resolve, reject) => {
            let current_status = xdom.session.status;
            xdom.session.updateSession(server_status);
            if (current_status != server_status.status) {
                xdom.stores.active.render();
            }
            resolve(server_status["status"]);
        });
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.session, 'login', {
    value: function () {
        if ('login' in xdom.server) {
            try {
                return xdom.server.login.apply(xdom.server, arguments);
            } catch (e) {
                console.error(e);
            }
        } else {
            xdom.session.status = 'authorized';
            return false;
        }
    }
    , writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.session, 'logout', {
    value: function () {
        if ('logout' in xdom.server) {
            try {
                return xdom.server.logout.apply(xdom.server, arguments);
            } catch (e) {
                console.error(e);
            }
        } else {
            xdom.session.status = 'unauthorized';
            xdom.init();
            return false;
        }
    }
    , writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.session, 'use', {
    value: function (database_id, without_confirmation) {
        if (!(xdom.session.database_id == database_id)) {
            if (!without_confirmation && confirm("Change connection?")) {
                xdom.session.database_id = database_id;
                xdom.session.logout();
            }
        }
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.session, 'saveLocation', {
    value: function (key, value) {
        xdom.session.setKey("xdom.current_location", window.location.pathname.replace(/[^/]+$/, ""));
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.session, 'getLocation', {
    value: function () {
        return xdom.session.getKey("xdom.current_location");
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.session, 'setData', {
    value: function (data) {
        if (typeof (Storage) !== "undefined") {
            if (data && data.documentElement) {
                data = data.documentElement.outerHTML;
            }
            xdom.session.setKey(location.pathname.replace(/[^/]+$/, "") + "xdom.data", data);
        }
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.session, 'clearCache', {
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
            //xdom.stores.clear();

        } else {
            console.error('Storage is not supported by your browser')
        }
    },
    writable: false, enumerable: false, configurable: false
});

xdom.state = new Proxy(Object.assign({}, history.state), {
    get: function (self, key) {
        let proxy = self;
        if (!history.state) {
            with ((window.top || window)) {
                history.replaceState({}, {}, location.pathname + (location.hash || ''));
                history.replaceState(proxy, {}, location.pathname + (location.hash || ''));
            }
            xdom.session.setKey('lastPosition', self.position);
        }
        if (self.hasOwnProperty(key)) {
            return self[key];
        } else {
            return xdom.session.getKey(key);
        }
    },
    set: function (self, key, value) {
        try {
            self[key] = value;
        } catch (e) {
            console.error(e);
        }
    }
})

Object.defineProperty(xdom.state, 'prev', {
    get() { return (history.state['prev'] || []) }
    , set() { throw `State "prev" is readonly` }
    , enumerable: true
});
Object.defineProperty(xdom.state, 'hash', {
    get() { return location.hash }
    , set(input) {
        input = input[input.length - 1] != '#' ? input : '';
        let new_state = Object.assign({}, this, { active: history.state.active });
        history.replaceState(new_state, ((event || {}).target || {}).textContent, location.pathname + (input || ''));
    }
    , enumerable: false
});

Object.defineProperty(xdom.state, 'stores', {
    get() { return (history.state['stores'] || {}) }
    , set(input) { history.state['stores'] = input }
    , enumerable: true
});
Object.defineProperty(xdom.state, 'activeCaret', {
    get() {
        let active = this.active;
        let state_stores = this.stores;
        return (state_stores[active] || {})["activeCaret"];
    }
    , set(input) {
        let active = this.active;
        let state_stores = this.stores;
        state_stores[active] = (state_stores[active] || {});
        state_stores[active]["activeCaret"] = input;
    }
    , enumerable: false
});
Object.defineProperty(xdom.state, 'activeElement', {
    get() {
        targetDocument = ((document.activeElement || {}).contentDocument || document);
        let active = this.active;
        let state_stores = this.stores;
        return targetDocument.querySelector((state_stores[active] || {})["activeElement"]) || (document.activeElement || {});
    }
    , set(input) {
        if (input instanceof Node) input = input.selector;
        let active = this.active;
        let state_stores = this.stores;
        state_stores[active] = (state_stores[active] || {});
        state_stores[active]["activeElement"] = input;
    }
    , enumerable: false
});
Object.defineProperty(xdom.state, 'next', {
    get() { return (history.state['next'] || {}) }
    , set(input) { history.state['next'] = input }
    , enumerable: false
});
Object.defineProperty(xdom.state, 'seed', {
    get() { return (history.state['seed'] || location.hash || '#') }
    , set(input) {
        if (!history.state['seed']) {
            history.state['seed'] = input;
            //xdom.state.active = input;
        } else if (history.state['seed'] != input) {
            this.next = input;
            var prev = this["prev"];
            prev.unshift(history.state.seed)
            history.pushState({
                seed: input
                , prev: prev
            }, ((event || {}).target || {}).textContent, xdom.stores[input].tag);
        }
    }
    , enumerable: true
});
Object.defineProperty(xdom.state, 'scrollableElements', {
    get() { return (history.state['scrollableElements'] || {}) }
    , set(input) { history.state['scrollableElements'] = input }
    , enumerable: true
});
Object.defineProperty(xdom.state, 'position', {
    get() { return [history.state['position'], Number(this.prev.length) + 1].coalesce() }
    , set(input) { history.go(input - xdom.state.position) }
    , enumerable: true
});

Object.defineProperty(xdom.state, 'active', {
    get: function () {
        if (xdom.session.getKey("status") != 'authorized' && 'login' in xdom.server) {
            return "#login";
        } else {
            return history.state.active || this.seed;
        }
    },
    set: function (input) {
        /* No debe ser modificable */
        //Object.defineProperty(this, "active", { value: input });
        //xdom.stores.active.render(/*true*/);
        //let hash = [xdom.stores[input].hash, (window.top || window).location.hash].coalesce();
        //xdom.dom.navigateTo(hashtag)
        let store = xdom.stores[input];
        if ([this.seed, (xdom.stores[this.seed] || {}).tag, ...this.activeTags()].filter(store => store).includes(store.tag) || store.isRendered) { //TODO: Revisar si isRendered siempre 
            //history.state.active = input; //No lo tiene que guardar, porque en el caso del login, sobreescribiría el estado y lo perderíamos. Este truco se va a tener que hacer directo con history.state.active
            let active_store = xdom.stores[this.active];
            if (active_store) {
                this.hash = active_store.hash;
            }
            //active_store.render();
        } else if (input in xdom.stores) {
            this.seed = input
        } else {
            throw (`Store ${input} doesn't exist`)
        }
    }
    , enumerable: false
});

Object.defineProperty(xdom.state, 'activeTags', {
    get: function () {
        return function (tag) {
            let active_tag = tag || (xdom.stores[this.active] || {}).tag || this.active; //se hace de esta manera porque el estado podría guardar como active el tag "#"
            this.stores[active_tag] = this.stores[active_tag] || {};
            let active_stores = (this.stores[active_tag] || {}).active;
            return active_stores || [(xdom.stores[this.active] || {}).tag].filter(tag => tag);
        }
    }
    , set: function (input) {
        let self = this;
        let active = self.active;
        let state_stores = self.stores;
        state_stores[active] = (state_stores[active] || {});
        state_stores[active]["active"] = input;
    }
    , enumerable: false
});

Object.defineProperty(xdom.state, 'update', {
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

Object.defineProperty(xdom.state, 'detectActive', {
    value: function () {
        //let active_tag = self.tag;
        let active_tags = [...window.document.querySelectorAll(`[xo-store]`)].reduce((new_target, el) => { let tag = el.getAttribute("xo-store"); new_target.push(tag); return new_target; }, []);
        this.activeTags = [...new Set(active_tags)];
        //let state_stores = this.stores;
        //state_stores[active_tag] = (state_stores[active_tag] || {})
        //state_stores[active_tag]["active"] = active_tags;
        //xdom.state.activeTags = [...new Set([xdom.state.activeTags(), active_tags].flat())];
        //return state_stores[active_tag]["active"];
    }
    , enumerable: false, configurable: false
});

Object.defineProperty(xdom.state, 'save', {
    value: function (srcElement) {
        //xdom.delay(1).then(() => {
        //srcElement = (srcElement || event && event.srcElement);
        targetDocument = ((document.activeElement || {}).contentDocument || document);
        //if (srcElement && !(srcElement instanceof HTMLElement) || !targetDocument.querySelector('*')) {
        //    return
        //}
        srcElement = srcElement || targetDocument.querySelector(this.activeElement.selector || this.activeElement);
        if (srcElement) {
            this.activeElement = srcElement.selector;
            this.activeCaret = xdom.dom.getCaretPosition(srcElement);
        }
        //console.log(this.activeElement)
        //console.log(this.activeCaret)
        xdom.dom.updateScrollableElements();
        //})
    }
    , enumerable: false, configurable: false
});

Object.defineProperty(xdom.state, 'restore', {
    value: function (scope) {
        targetDocument = (scope || (document.activeElement || {}).contentDocument || document);
        //var linkEls = targetDocument.querySelectorAll('a');
        //for (link of linkEls) {
        //    link.addEventListener('click', () => { new xdom.listener.Event('click', [hashtag, (window.top || window).location.hash]) }, true);
        //}

        let activeElement = xdom.state.activeElement
        Object.entries(xdom.state.scrollableElements).map(([selector, coordinates]) => {
            xdom.dom.setScrollPosition(targetDocument.querySelector(selector), coordinates)
        })
        if (!activeElement) {
            return;
        }
        xdom.dom.triggeredByTab = undefined;
        xdom.dom.setCaretPosition(activeElement, xdom.state.activeCaret);
    }
    , enumerable: false, configurable: false
});

xdom.Source = function (source, tag) {
    let _isActive = undefined;
    let self = this;
    let __document = xdom.xml.Empty();
    if (!(this instanceof xdom.Source)) return new xdom.Source(source, tag);
    Object.defineProperty(this, 'source', {
        value: source,
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'tag', {
        value: tag,
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'document', {
        enumerable: true,
        get: function () {
            return __document;
        }
    });

    Object.defineProperty(this, 'find', {
        value: [],
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'selectSingleNode', {
        enumerable: true,
        get: function () {
            return __document.selectSingleNode;
        }
    });

    Object.defineProperty(this, 'selectNodes', {
        enumerable: true,
        get: function () {
            return __document.selectNodes;
        }
    });

    Object.defineProperty(this, '$', {
        enumerable: true,
        get: function () {
            return __document.selectSingleNode;
        }
    });

    Object.defineProperty(this, '$$', {
        enumerable: true,
        get: function () {
            return __document.selectNodes;
        }
    });
    Object.defineProperty(this, 'render', {
        value: async function () {
            try {
                let store = await this.fetch();
                if (store instanceof xdom.Store && 'render' in store) {
                    return store.render(/*true*/);
                }
                return store;
            } catch (e) {
                Promise.reject(e);
            }
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(this, 'isActive', {
        enumerable: true,
        get: function () {
            let tag = self.tag;
            return _isActive !== false && (tag === xdom.stores.active.tag || /*self.isRendered || */(xdom.state.activeTags() || [tag]).includes(tag));
        },
        set: function (input) {
            xdom.state.active = self.tag;
        }
    });

    this.state = new Proxy({}, {
        get: function (target, name) {
            return target[name];
        },
        set: function (target, name, value) {
            target[name] = value
        }
    })

    if (isFunction(source)) {
        Object.defineProperty(this, 'fetch', {
            get: function () {
                return async function () {
                    try {
                        return source.apply(this, [...(arguments.length && arguments || [tag])]);
                    } catch (e) {
                        Promise.reject(e);
                    }
                }
            }
        });
    } else if (isObject(source) && source["url"]) {
        Object.defineProperty(this, 'fetch', {
            value: async function () {
                try {
                    let document = await xdom.fetch.xml(url, source);
                    document instanceof Document && source["stylesheets"] && source["stylesheets"].reverse().map(stylesheet => {
                        document.addStylesheet(stylesheet);
                    });
                    document = new xdom.Store(document, { tag: tag });
                    await document.render(/*true*/);
                    if (!document.isRendered) {
                        xdom.stores.active = document;
                    }
                    return document;
                } catch (e) { }
            },
            writable: false, enumerable: false, configurable: false
        });
    } else if (isObject(source)) {
        Object.defineProperty(this, 'fetch', {
            value: async function () {
                let promises = []
                Object.keys(source).filter(endpoint => endpoint in xdom.server && xdom.server[endpoint]).map(async (endpoint) => {
                    let [parameters, options = {}, payload] = source[endpoint].constructor === [].constructor && source[endpoint] || [source[endpoint]];
                    options["tag"] = options["tag"] || tag;
                    promises.push(new Promise(async (resolve, reject) => {
                        let document = await xdom.server[endpoint].apply(this, [parameters, options, payload]);
                        await document.render(/*true*/);
                        if (document instanceof XMLDocument && !document.isRendered) {
                            xdom.stores.active = document;
                        }
                        resolve(document);
                    }));
                })
                await Promise.all(promises);
                return xdom.stores[tag];
            },
            writable: false, enumerable: false, configurable: false
        });
    } else {
        Object.defineProperty(this, 'fetch', {
            value: async function () {
                try {
                    let document = await xdom.fetch.xml(source, { rejectCodes: 400 });
                    document = new xdom.Store(document, { tag: tag });
                    return document.render(/*true*/);
                    //if (!document.isRendered) { TODO: Revisar como hacer que esto se pueda hacer evitar que cuando la llamada sea de render, no reemplace al active original.
                    //    xdom.stores.active = document;
                    //}
                    //return xdom.stores[tag];
                } catch (e) {
                    throw (e);
                }

                if (tag) {
                    !xdom.stores[tag]
                } else {
                    xdom.stores[document.tag];
                }
            },
            writable: false, enumerable: false, configurable: false
        });
    }
    return this
}

xdom.sources = new Proxy({}, {
    get: function (self, key) {
        var _manifest = (xdom.manifest.sources || {}).cloneObject();
        var value = undefined;
        do {
            if (_manifest.hasOwnProperty(value)) {
                key = value;
            }
            value = _manifest[key];
            delete _manifest[key]; //se borra para evitar referencias cíclicas
        } while (_manifest.hasOwnProperty(value))
        value = value || Object.entries(xdom.manifest.sources || {}).find(([tag]) => key.match(new RegExp(`^${tag.replace(/[-[\]{}()*+?.,\\^$|#]/g, '\\$&')}$`)))[1]; //TODO: Agregar opción para tags con expresiones regulares
        if (!value) {
            return null;
        }
        return new xdom.Source(value, key)
    },
    has: function (self, key) {
        return source_defined = key in self || !!Object.entries(xdom.manifest.sources || {}).find(([tag]) => key.match(new RegExp(`^${tag.replace(/[-[\]{}()*+?.,\\^$|#]/g, '\\$&')}$`)))
    }
})

xdom.ProcessingInstruction = function (stylesheet) {
    if (!(this instanceof xdom.ProcessingInstruction)) return new xdom.ProcessingInstruction(stylesheet);
    let attribs = xdom.json.fromAttributes(stylesheet.data);
    attribs["dependencies"] = [];
    if (attribs.target) {
        attribs["target"] = ((attribs["target"] || '').replace(new RegExp("@(#[^\\s\\[]+)", "ig"), "[xo-store='$1']") || undefined);
        attribs["dependencies"] = [...attribs["target"].matchAll(new RegExp(`\\[xo-store=('|")([^\\1\\]]+)\\1\\]`, 'g'))].reduce((arr, curr) => { arr.push(curr[2]); return arr }, []);
    }
    for (let prop in attribs) {
        Object.defineProperty(stylesheet, prop, {
            value: attribs[prop],
            writable: true, enumerable: true, configurable: false
        });
    }
    if (!stylesheet.hasOwnProperty("document")) {
        Object.defineProperty(stylesheet, 'document', {
            get: function () {
                this.ownerDocument.store = this.ownerDocument.store || (xdom.stores.find(this.ownerDocument).shift() || document.createElement('p')).store //Se pone esta solución pero debería tomar automáticamente el store. Ver si se puede solucionar este problema de raíz.
                return this.ownerDocument.store && this.ownerDocument.store.library[this.href] || xdom.library[this.href] || xdom.library.load(this.href);
            }
        });
    }
    if (!stylesheet.href) {
        console.warn('Href attribute is missing from stylesheet!');
    }
    Object.setPrototypeOf(stylesheet, xdom.ProcessingInstruction.prototype)
    return stylesheet;
}

xdom.ProcessingInstruction.prototype = Object.create(ProcessingInstruction.prototype);

xdom.storage = {};
xdom.tracking = {};
xdom.tracking.attributes = [];
xdom.tracking.prefixes = [];
xdom.fetch = {};
xdom.xml = {};
xdom.xml.namespaces = {};
xdom.xml.namespaces["debug"] = "http://panax.io/debug"
xdom.xml.namespaces["js"] = "http://panax.io/xdom/javascript"
xdom.xml.namespaces["session"] = "http://panax.io/session"
xdom.xml.namespaces["shell"] = "http://panax.io/shell"
xdom.xml.namespaces["state"] = "http://panax.io/state"
xdom.xml.namespaces["context"] = "http://panax.io/context"
xdom.xml.namespaces["temp"] = "http://panax.io/temp"
xdom.xml.namespaces["xmlns"] = "http://www.w3.org/2000/xmlns/"
xdom.xml.namespaces["x"] = "http://panax.io/xdom"
xdom.xml.namespaces["xo"] = "http://panax.io/xdom"
xdom.xml.namespaces["xson"] = "http://panax.io/xson"
xdom.xml.namespaces["metadata"] = "http://panax.io/metadata"
xdom.xml.namespaces["xml"] = "http://www.w3.org/XML/1998/namespace"
xdom.xml.namespaces["xsl"] = "http://www.w3.org/1999/XSL/Transform"
xdom.xml.namespaces["xsi"] = "http://www.w3.org/2001/XMLSchema-instance"
xdom.xml.namespaces["mml"] = "http://www.w3.org/1998/Math/MathML"
xdom.xml.namespaces["transformiix"] = "http://www.mozilla.org/TransforMiix"
xdom.xml.namespaces["session"] = "http://panax.io/session"
xdom.xml.namespaces["transforms"] = "http://panax.io/transforms"
xdom.xml.namespaces["xhtml"] = "http://www.w3.org/1999/xhtml"

/* Binding */
xdom.xml.namespaces["request"] = "http://panax.io/fetch/request"
xdom.xml.namespaces["source"] = "http://panax.io/fetch/request"
xdom.xml.namespaces["binding"] = "http://panax.io/xdom/binding"
xdom.xml.namespaces["changed"] = "http://panax.io/xdom/binding/changed"
xdom.xml.namespaces["source_text"] = "http://panax.io/fetch/request/text"
xdom.xml.namespaces["source_prefix"] = "http://panax.io/fetch/request/prefix"
xdom.xml.namespaces["source_value"] = "http://panax.io/fetch/request/value"
xdom.xml.namespaces["source_filters"] = "http://panax.io/fetch/request/filters"
xdom.xml.namespaces["source_fields"] = "http://panax.io/fetch/request/fields"
/* Values */
xdom.xml.namespaces["confirmed"] = "http://panax.io/xdom/state/confirmed"
xdom.xml.namespaces["suggested"] = "http://panax.io/xdom/state/suggested"
xdom.xml.namespaces["initial"] = "http://panax.io/xdom/state/initial"
xdom.xml.namespaces["prev"] = "http://panax.io/xdom/state/previous"
xdom.xml.namespaces["fixed"] = "http://panax.io/xdom/state/fixed"

xdom.dom.alert = async function (message) {
    let xMessage = xdom.data.createMessage(message)
    xMessage.addStylesheet({ href: "message.xslt", role: "modal" })
    dom = await xMessage.transform();
    document.body.appendChild(dom.documentElement)
    return dom.documentElement;
}

xdom.dom.createDialog = function (message) {
    if (!message) { return null }
    let dialog_id = `dialog_${xdom.cryptography.generateUUID()}`
    let dialog = document.querySelector(`#${dialog_id}`);
    if (!dialog) {
        let frag = window.document.createDocumentFragment();
        let p = window.document.createElement('p');
        p.innerHTML = `<dialog id="${dialog_id}"><form method="dialog" onsubmit="closest('dialog').remove()"><section></section><menu><button type="submit">Close</button></menu></form></dialog>`;
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
    }

    dialog.querySelector("section").append(message);
    document.querySelector(`#${dialog_id}`);
    dialog.showModal();
    return dialog;
}

Object.defineProperty(xdom.session, 'updateSession', {
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
            xdom.session[pair[0]] = pair[1];
        }
        /*Se deshabilita la actualización por default*/
        if (sync && navigator.onLine && (xdom.manifest.server || {}).endpoints["session"] && await xdom.session.status == 'authorized') {
            xdom.post.to((xdom.manifest.server || {}).endpoints["session"], session_variables).catch(() => {
                console.log("Error al enviar sesión")
            })
        }
        return Promise.all([...session_variables.keys()].map((key) => xdom.session[key]));
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.session, 'user_login', {
    get: function () {
        return xdom.session.getKey("user_login")
    }
    , set: function (input) {
        if (xdom.session.getKey("user_login") != input) {
            xdom.session.id_token = undefined;
        }
    }
});

Object.defineProperty(xdom.session, 'connection_id', {
    get: function () {
        return xdom.session.getKey("database_id")
    }
    , set: function (input) {
        xdom.session.database_id = input;
    }
});

//var __database_id_getter = function () { return xdom.session.getKey("database_id") }  /*muestra de getter dinámico*/
Object.defineProperty(xdom.session, 'database_id', {
    get: function () {
        return (xdom.manifest.server && isFunction(xdom.manifest.server.database_id) && xdom.manifest.server.database_id() || xdom.session.getKey("database_id") || xdom.manifest.server.database_id)
    }
    , set: async function (input) {
        xdom.dom.refreshTitle();
    }
});

Object.defineProperty(xdom.session, 'connect', {
    value: function (input) {
        xdom.session.id = (input || xdom.session.id || xdom.cryptography.generateUUID());
        return xdom.session.id;
    },
    writable: true, enumerable: false, configurable: false
});

Object.defineProperty(xdom.session, 'disconnect', {
    value: function (input) {
        xdom.session.id = undefined;
        return xdom.session.id;
    },
    writable: true, enumerable: false, configurable: false
});

Object.defineProperty(xdom.session, 'cache_name', {
    get: function () {
        return xdom.session.getKey("cache_name") || "";
    }
    , set() { }
});

xdom.browser.isIE = function () {
    var ua = window.navigator.userAgent;
    return /MSIE|Trident/.test(ua) && !xdom.browser.isEdge();
}

xdom.browser.isEdge = function () {
    var ua = window.navigator.userAgent;
    return /Edge/.test(ua);
}

xdom.browser.isSafari = function () {
    var ua = window.navigator.userAgent;
    return /Safari/.test(ua);
}

xdom.browser.isIphone = function () {
    return navigator.userAgent.match(/iPhone/i);
}

xdom.browser.isIPad = function () {
    return navigator.userAgent.match(/iPad/i);
}

xdom.browser.isIOS = function () {
    return xdom.browser.isIphone() || xdom.browser.isIPad() || navigator.userAgent.match(/Macintosh/i);
}

Object.defineProperty(xdom.debug, 'enabled', {
    get: function (ref) {
        return xdom.session.debug;
    }
    , set: function (input) {
        xdom.session.debug = !!input;
    }
});

xdom.Manifest = function (manifest) {
    let base_manifest = {
        "server": { "database_id": undefined, "endpoints": {} },
        "sources": {},
        "transforms": [],
        "namespaces": {},
        "modules": {}
    }
    var _manifest = base_manifest.merge(manifest || {});

    Object.defineProperty(_manifest.sources, 'fetch', {
        value: async function (key) {
            let important_sources = Object.entries(_manifest.sources).filter(([_key, _value]) => _key.match(/!$/));
            let tag = String(_manifest.sources[history.state.hash || (window.top || window).location.hash || "#"]).match(/^#/) && _manifest.sources[history.state.hash || (window.top || window).location.hash || "#"] || (window.top || window).location.hash || "#";

            to_fetch = [...(key && _manifest.sources[key] && [[tag, _manifest.sources[key]]] || []), ...(!key && tag != '#' && !xdom.stores[tag] && _manifest.sources[tag] && [[tag, _manifest.sources[tag]]] || [])];

            if (to_fetch.length) {
                to_fetch.map(async ([_key, _value]) => {
                    //if (_key == "#" && typeof (_value) == "string" && _manifest.sources[_value]) {
                    //    var doc = _value.fetch({ as: _value });
                    //    xdom.stores.active = doc;
                    //} else {
                    var doc = await _value.fetch({ as: _key });
                    if (doc) {
                        xdom.stores.active = doc;
                    }
                    //}
                });
            } else if (!key && xdom.stores[tag]) {
                xdom.stores.active = xdom.stores[tag];
            }
            //}
        },
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(_manifest, 'getConfig', {
        value: (xdom.manifest.getConfig || function (entity_name, config_name) {
            return (_manifest.modules[entity_name]
                || _manifest.modules[entity_name.toLowerCase()]
                || {})[config_name]
        }),
        writable: true, enumerable: false, configurable: false
    });

    //TODO: Revisar si esta sección se queda.
    //Object.defineProperty(_manifest, 'setConfig', {
    //    value: function (entity_name, property_name, value) {
    //        if (arguments[0].constructor === {}.constructor) {
    //            const { entity_name, ...rest } = arguments[0];
    //            _manifest.modules[(entity_name || xdom.data.hashTagName())] = (_manifest.modules[(entity_name || xdom.data.hashTagName)] || {})
    //            xdom.json.merge(_manifest.modules[(entity_name || xdom.data.hashTagName())], rest);
    //        } else {
    //            _manifest.modules[(entity_name || xdom.data.hashTagName())] = (_manifest.modules[(entity_name || xdom.data.hashTagName())] || {});
    //            _manifest.modules[(entity_name || xdom.data.hashTagName())][property_name] = value
    //        }
    //    },
    //    writable: true, enumerable: false, configurable: false
    //});

    return _manifest;
}

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
    xdom.data.update({
        target: control.id
        , attributes: [{ '@value': new_string_date }, { '@text': new_string_date }]
    });
    return new_string_date;
}

function isValidDate(sDate) {
    var full_pattern = /\b(\d{1,2})(?:(\/)(\d{1,2})(?:\2(\d{2,4})))/
    return (sDate.match(full_pattern) && Date.parse(sDate) != 'NaN');
}

function isValidISODate(sDate) {
    var full_pattern = /\b(\d{4})(?:(-)(\d{1,2})(?:\2(\d{1,2})))/
    return (sDate.match(full_pattern) && Date.parse(sDate) != 'NaN' && (new Date().getFullYear()) - (new Date(Date.parse(sDate)).getFullYear()) < 1000);
}

xdom.dom.getGeneratedPageURL = function (config) {
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

Object.defineProperty(xdom.server, 'uploadFile', {
    value: async function (source) {
        if (!(xdom.manifest.server["endpoints"] && xdom.manifest.server["endpoints"]["uploadFile"])) {
            throw ("Endpoint for uploadFile is not defined in the manifest");
        }
        let file;
        if (source instanceof HTMLElement && source.type === 'file') {
            file = source.files && source.files[0]
            file.id = source.id;
            file.saveAs = source.saveAs;
        } else if (source instanceof File) {
            file = source;
            file.id = file.id || source.id;
            file.saveAs = file.saveAs || file.name;
        } else if (source instanceof Node && source.nodeType === 2) {
            let record = await (await xdom.database.files).get(source.value);
            file = record.file;
            file.id = record.id;
            file.saveAs = record.saveAs;

            if (!file) {
                source.selectSingleNode('..').setAttribute(source.name, '');
                throw ('Invalid file, upload again');
            }
        }
        if (file) {
            //var progress_bar = document.getElementById('_progress_bar_' + control.id);
            //progress_bar.style.width = '0%';
            //
            //var that = this;
            //if (xdom.dom.intervals[control.id]) delete xdom.dom.intervals[control.id];
            //if (xdom.manifest.server["endpoints"] && xdom.manifest.server["endpoints"]["uploadFileManager"]) {
            //    xdom.dom.intervals[control.id] = setInterval(function () {
            //        var upload_check = new XMLHttpRequest();
            //        upload_check.open('GET', xdom.manifest.server["endpoints"]["uploadFileManager"] + '?UploadID=' + control.id);// + control.id);
            //        upload_check.onreadystatechange = function (oEvent) {
            //            if (upload_check.readyState === 4) {
            //                var json_response = JSON.parse(upload_check.responseText);
            //                var progress_bar = document.getElementById('_progress_bar_' + control.id);
            //
            //                progress_bar.className = progress_bar.className.replace(/\bprogress-bar(-\w+)*\s*/ig, '')
            //                progress_bar.className = 'progress-bar progress-bar-striped progress-bar-animated ' + progress_bar.className;
            //
            //                if (String(Number.parseFloat(progress_bar.style.width)) == 'NaN') {
            //                    progress_bar.style.width = '0%';
            //                }
            //                if (json_response.percent > Number.parseFloat(progress_bar.style.width)) {
            //                    progress_bar.style.width = json_response.percent + '%';
            //                }
            //            }
            //        };
            //        upload_check.send();
            //    }, 200);
            //}


            return new Promise((resolve, reject) => {
                let reader = new FileReader();
                reader.onload = function (e) {
                    var formData = new FormData();
                    formData.append(file.name, file);

                    //var request = new XMLHttpRequest();
                    let request = new xdom.Request(xdom.manifest.server["endpoints"]["uploadFile"] + `?UploadID=${file.id}&saveAs=${file.saveAs}&parentFolder=${(file.parentFolder || '').replace(/\//g, '\\')}`, { method: 'POST', body: formData })
                    fetch(request).then(async response => {
                        let file_name = response.headers.get("File-Name");
                        if (source && source instanceof Node) {
                            let temp_value = source.value;
                            [source, ...xdom.stores.find(`//@*[starts-with(.,'blob:') and .='${temp_value}']`)].map(attr => attr.selectSingleNode('..').setAttribute(attr.name, file_name));
                        }
                        var progress_bar = document.getElementById('_progress_bar_' + file.id);
                        if (progress_bar) {
                            progress_bar.style.width = '100%';
                            progress_bar.className = progress_bar.className.replace(/\bbg-\w+/ig, 'bg-success');
                            progress_bar.className = progress_bar.className.replace(/\progress-bar-\w+/ig, '');
                        }
                        resolve();
                        //console.log(request.responseText)
                        //let res = new xdom.Response(response, request);;
                        //let document = await res.processBody();
                        //console.log(document);
                    })
                    //request.onreadystatechange = function (oEvent) {
                    //    if (request.readyState === 4) {
                    //        delete xdom.dom.intervals[file.id];
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
            });
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

xdom.data.updateScrollPosition = function (document, coordinates) {
    var target = coordinates.target;
    if (target) {
        Object.entries(coordinates).forEach(([key, value]) => {
            if (key != 'target' && target.source) {
                target.source.setAttributeNS(null, `state:${key}-position`, value);
                //var attributeRef = target.selectSingleNode(`//@state:${key}-position`);
                //if (attributeRef) {
                //    attributeRef.ownerElement.setAttributeNS(xdom.xml.namespaces["state"], `state:${key}-position`, value, false);
                //}
            }
        })
    }
}

xdom.dom.onscroll = function () {
    xdom.dom.onscroll.Promise = xdom.dom.onscroll.Promise || xdom.delay(500).then(async () => {
        Object.entries(xdom.state.scrollableElements).map(([selector, coordinates]) => {
            let scroll_data = xdom.dom.getScrollPosition(document.querySelector(selector))
            xdom.dom.scrollableElements[selector]["x"] = scroll_data["x"] || 0
            xdom.dom.scrollableElements[selector]["y"] = scroll_data["y"] || 0
        })
        xdom.dom.updateScrollableElements();
        xdom.dom.onscroll.Promise = undefined;
    });
    return xdom.dom.onscroll.Promise
    //xdom.dom.position = xdom.dom.getScrollPosition();//document.getElementsByClassName("w3-responsive")[0] || document.querySelector('main')
    //xdom.data.updateScrollPosition(xdom.stores.active, xdom.dom.position);
}

//document.addEventListener('scroll', function () {
//    xdom.dom.onscroll()
//});

document.addEventListener("DOMContentLoaded", function (event) {
    document.body.addEventListener('scroll', xdom.dom.onscroll);
    //Object.values((xdom.dom.getScrollableElements() || {})).forEach(
    //    el => el.addEventListener('scroll', xdom.dom.getScrollPosition)
    //);
    //xdom.init();
});

window.addEventListener("focusin", function (event) {
    xdom.state.save(event.target);
});

document.addEventListener("selectionchange", function (event) {
    let target = document.getSelection().focusNode;
    if (target && target.nodeName == '#text') {
        xdom.state.save(target);
    }
});

var content_type = {}
content_type["json"] = "application/json";
content_type["xml"] = "text/xml";

xdom.library = new Proxy({}, {
    get: function (self, key) {
        let document;
        if (key in self) {
            document = self[key];
        } else {
            document = self.defaults[key];
        }
        if (document instanceof Document) {
            Object.defineProperty(document, "href", {
                value: key
                , writable: true, enumerable: true, configurable: false
            })
        }
        return document;
    },
    set: function (self, key, input) {
        self[key] = input;
        return self[key];
    }
});

Object.defineProperty(xdom.library, 'defaults', {
    value: {},
    writable: true, enumerable: false, configurable: false
});

Object.defineProperty(xdom.library, 'loading', {
    value: [],
    writable: true, enumerable: false, configurable: false
});

Object.defineProperty(xdom.library, 'load', {
    value: async function (file_name_or_array) {
        if (!file_name_or_array) return null;
        let simple_output = typeof (file_name_or_array) == 'string';
        let _file_name_or_array = (file_name_or_array || []);
        let library = {};
        _file_name_or_array = [...new Set([_file_name_or_array].flat())];
        //_file_name_or_array = _file_name_or_array.filter((file_name) => !(xdom.library.loading.includes(file_name) || file_name in this));
        _file_name_or_array.map((file_name) => xdom.library.loading.push(file_name));
        _file_name_or_array.map(file_name => {
            let full_url = new URL(file_name, location.origin + location.pathname.replace(/[^/]+$/, ""));
            let url = full_url.href.replace(new RegExp(`^${location.origin}`), "").replace(new RegExp(`^${location.pathname.replace(/[^/]+$/, "")}`), "").replace(/^\/+/, '')
            if (url in this && this[url]) {
                library[url] = this[url];
            } else {
                this[url] = xdom.fetch(full_url)
                    .then(response => [response.body, response.request])
                    .then(async ([data, request]) => {
                        let url = request.url.toString().replace(new RegExp(`^${location.origin}`), "").replace(new RegExp(`^${location.pathname.replace(/[^/]+$/, "")}`), "").replace(/^\/+/, '')
                        xdom.xml.namespaces.merge(xdom.xml.getNamespaces(data));
                        data.documentElement && data.documentElement.selectNodes("xsl:import|xsl:include").map(async node => {
                            let href = node.getAttribute("href");
                            if (!href.match(/^\//)) {
                                let new_href = new URL(href, data.url).pathname.replace(new RegExp(location.pathname.replace(/[^/]+$/, "")), "");
                                node.setAttributeNS(null, "href", new_href);
                            }
                        });
                        this[url] = xdom.xml.createDocument(data);
                        xdom.library.loading = xdom.library.loading.filter(item => item != url);
                        library[url] = this[url];
                        let imports = this[url].documentElement && this[url].documentElement.selectNodes("xsl:import|xsl:include").reduce((arr, item) => { arr.push(item.getAttribute("href")); return arr; }, []) || [];
                        if (imports.length) {
                            await xdom.library.load(imports);
                        }
                    }).catch(error => {
                        console.error(`Exception downloading ${url}: ${error}`);
                    })
            }
        })
        await Promise.all(_file_name_or_array.reduce((lib, stylesheet) => { lib.push(xdom.library[stylesheet]); return lib }, []));
        if (simple_output) {
            return Object.values(library).pop();
        } else {
            return library;
        }
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.library, 'reload', {
    value: function (file_name_or_array, on_complete) {
        Object.values(xdom.stores).map(store => {
            //(store.documentElement || document.createElement("p")).setAttributeNS(null, "state:refresh", true);
            if (store.library) {
                store.library = undefined;
            }
        });
        var current_keys = xdom.library.cloneObject();

        var file_name_or_array = (file_name_or_array || Object.keys(current_keys));
        if (typeof (file_name_or_array) == 'string') {
            file_name_or_array = [file_name_or_array];
        }
        for (let document_index = 0; document_index < file_name_or_array.length; document_index++) {
            var file_name = file_name_or_array[document_index];
            if (file_name in xdom.library) {
                xdom.library[file_name] = undefined;
            }
        }
        //var storage_enabled = xdom.storage.enabled;
        //if (storage_enabled) {
        //    xdom.storage.disable(file_name_or_array);
        //}
        xdom.library.load(file_name_or_array).then(response => {
            if (((xdom.manifest.server || {}).endpoints || {}).session) {
                xdom.session.checkStatus().then(() => xdom.dom.refresh());
            }
        });
        //xdom.library.load(file_name_or_array, (on_complete || function () {
        //    xdom.session.checkStatus().then(() => xdom.dom.refresh());
        //}));
        //if (storage_enabled) {
        //    xdom.storage.enable();
        //}
    },
    writable: true, enumerable: false
});

Object.defineProperty(xdom.library, 'reset', {
    value: function (file_name_or_array) {
        var _file_name_or_array = (file_name_or_array || Object.keys(xdom.library));
        if (typeof (_file_name_or_array) == 'string') {
            _file_name_or_array = [_file_name_or_array];
        }
        _file_name_or_array.map((file_name) => {
            if (file_name in xdom.library) {
                xdom.library[file_name] = undefined;
            }
        });
    },
    writable: true, enumerable: false
});

Object.defineProperty(xdom.library, "xdom/normalize_namespaces.xslt", {
    get: function () {
        return xdom.xml.createDocument(`
        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
          <xsl:output method="xml" indent="no" omit-xml-declaration="yes"/>
          <xsl:template match="@* | node() | text()" priority="-1">
            <xsl:copy>
              <xsl:copy-of select="//namespace::*"/>
              <xsl:copy-of select="@*|*|text()"/>
            </xsl:copy>
          </xsl:template>
        </xsl:stylesheet>
        `)
    }
})

Object.defineProperty(xdom.library, "xdom/databind.xslt", {
    get: function () {
        return xdom.xml.createDocument(`
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:x="http://panax.io/xdom"
  xmlns:source="http://panax.io/fetch/request"
  xmlns:prev="http://panax.io/xdom/state/previous"
  xmlns:changed="http://panax.io/xdom/binding/changed"
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

  <xsl:template match="source:*/*/@x:id" priority="-1"/>

  <xsl:template match="source:*[key('sourcedefinition',concat(generate-id(..),'::',local-name(),'::'))]"/>

  <xsl:template match="@source:*[.!='']" mode="sources">
    <xsl:param name="ref" select=".."/>
    <xsl:param name="mode">nodes</xsl:param>
    <xsl:variable name="attribute_name" select="local-name()"/>
    <xsl:variable name="curr_value" select="../@x:*[local-name()=$attribute_name and .!='' and .!='NULL']"/>
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
    <xsl:variable name="selected_record" select="$current_datasource/x:r[@x:*[local-name()=$attribute_name]=$curr_value]"/>
    <xsl:choose>
      <xsl:when test="$mode='attributes'">
        <!-- Sólo pueden ir atributos en esta sección -->
        <xsl:if test="$curr_value and not($current_datasource)">
          <xsl:attribute name="prev:{local-name()}">
            <xsl:value-of select="$curr_value"/>
          </xsl:attribute>
        </xsl:if>
        <!--<xsl:attribute name="debug:selected_record">
          <xsl:value-of select="$selected_record/@x:id"/>
        </xsl:attribute>-->
        <xsl:copy-of select="$selected_record/@*[not(name()='x:id')]"/>
        <xsl:choose>
          <xsl:when test="$current_datasource and not($current_datasource[@command=$curr_source]) or contains($curr_source,'{{') and $curr_value">
            <xsl:if test="$curr_value">
              <xsl:attribute name="x:{local-name()}"></xsl:attribute>
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
            <xsl:element name="source:{local-name()}">
              <xsl:attribute name="x:id">
                <xsl:value-of select="concat('__request_',generate-id())"/>
              </xsl:attribute>
              <xsl:attribute name="changed:{local-name()}"></xsl:attribute>
              <xsl:attribute name="command">
                <xsl:value-of select="$curr_source"/>
              </xsl:attribute>
              <!--<xsl:if test="$curr_value">
                <xsl:element name="x:r">
                  <xsl:attribute name="x:{local-name()}">
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

Object.defineProperty(xdom.stores, "#", {
    get: function () {
        return xdom.manifest.sources && this[xdom.manifest.sources["#"]] || xdom.stores['#shell'];
    }
});

Object.defineProperty(xdom.stores, 'active', {
    get: function () {
        let store = xdom.stores[xdom.state.active] || xdom.stores[xdom.state.seed] || xdom.stores["#"];// || xdom.Store(`<?xml-stylesheet type="text/xsl" href="message.xslt" role="modal" target="body" action="append"?><x:message xmlns:x="http://panax.io/xdom" x:id="xhr_message_${Math.random()}"/>`);
        return store;
    }
    , set: async function (input) {
        if (input && typeof input.then == 'function') {
            input = await input;
        }
        if (!(input instanceof xdom.Store)) {
            input = new xdom.Store(input);
            //input.reseed();
        }

        if (input) {
            var hashtag = input.tag;// || xdom.data.hashTagName(input);
            if (hashtag == xdom.stores.active.tag) {
                var current_position = xdom.data.getScrollPosition();
                xdom.data.updateScrollPosition(input, current_position);
            }

            xdom.stores[hashtag] = input;
            //if (hashtag != (history.state.seed || (window.top || window).location.hash || xdom.stores["#"].tag)) {//(history.state.hash || (window.top || window).location.hash)
            if (!xdom.stores[hashtag].isActive) {
                //xdom.dom.history.push((window.top || window).location.hash);
                xdom.state.active = hashtag;
            } else {
                await xdom.stores[hashtag].render(/*true*/);
                [input.stylesheets["loading.xslt"]].removeAll();
            }
            //input.isActive = true;
            //xdom.dom.refresh({ forced: true });
        }
    }
});

Object.defineProperty(xdom.stores, 'detectActive', {
    value: function () {
        if ((xdom.state.activeTags() || []).includes(xdom.state.hash)) {
            var activeTags = [];
            [...document.querySelectorAll("[xo-store]")].filter(el => xdom.stores[el.getAttribute("xo-store")]).map(el => {
                activeTags.push(el.getAttribute("xo-store"));
            });
            xdom.state.activeTags = activeTags;
        }
        return this.getActive()
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.stores, 'find', {
    value: function (ref) {
        var return_array = [];

        var target = xdom.stores.active.find(ref);
        if (target) {
            //return_array.push([target, xdom.stores.active]);
            return_array.push(target);
        }
        //xdom.stores.filter((nombre, document) => document.selectSingleNode(`//*[@x:id="${typeof (ref) == 'string' ? ref : ref.getAttribute("x:id")}"]`))
        for (let xDocument in xdom.stores) {
            target = xdom.stores[xDocument].find(ref);
            if (target) {
                //return_array.push([target, xdom.stores[xDocument]]);
                return_array.push(target);
            }
        }
        Object.entries(sessionStorage).filter(([key]) => key.match(/^#/) && !xdom.stores.hasOwnProperty(key)).map(([hashtag, value]) => {
            let restored_document = xdom.session.getKey(hashtag)
            if (restored_document) {
                restored_document = new xdom.Store(restored_document, { tag: hashtag });
                if (restored_document.find(ref)) {
                    return_array.push(xdom.stores[hashtag].find(ref));
                }
            }
        })
        return_array = [...new Set(return_array)];
        return new xdom.NodeSet(return_array);
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.stores, 'getActive', {
    value: function (attribute, value) {
        let active = Object.entries(xdom.stores).reduce((json, [tag, store]) => {
            if (store && store.isActive) {
                json[tag] = store;
            };
            return json;
        }, {});

        Object.defineProperty(active, 'getInitiators', {
            value: function (attribute, value) {
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

Object.defineProperty(xdom.stores, 'getInactive', {
    value: function (attribute, value) {
        return Object.entries(xdom.stores).reduce((json, item) => { if (!(item[1].isActive)) { json[item[0]] = item[1]; }; return json }, {});
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.stores, 'clear', {
    value: function (attribute, value) {
        Object.keys(this).map(key => delete this[key]);
        sessionStorage.clear();
        return this;
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.stores, 'restore', {
    value: async function (name_list = []) {
        name_list = name_list instanceof Array && name_list || [name_list];
        var self = this;
        let stores = await xdom.database.stores;
        let cursor = await stores.openCursor();
        let restoring = [];
        cursor.filter(([key]) => (!name_list.length && !xdom.stores.hasOwnProperty(key) || name_list.includes(key)) && key.match(/^#/)).map(async ([hashtag, value]) => {
            restoring.push(value)
            let restored_document = await value; //(self[hashtag] || await value) //xdom.session.getKey(hashtag))
            //let restored_document = (self[hashtag] || xdom.session.getKey(hashtag))
            console.log('Restoring document ' + hashtag);
            if (!(restored_document instanceof xdom.Store)) {
                restored_document = new xdom.Store(restored_document, { tag: hashtag });
            }
            //if (!((restored_document.documentElement || {}).namespaceURI && restored_document.documentElement.namespaceURI.indexOf("http://www.w3.org") != -1)) {
            //    self[hashtag] = restored_document;
            //}
        })
        restoring = await Promise.all(restoring).then(document => document);
        return restoring;
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.stores, 'seed', {
    get: function () {
        return this[xdom.state.seed] || this["#"];
    }
});

var originalRemoveAttribute = Element.prototype.removeAttribute;
var originalRemove = Element.prototype.remove;
var replaceChild_original = Element.prototype.replaceChild
var setAttribute_original = Element.prototype.setAttribute;
var setAttributeNS_original = Element.prototype.setAttributeNS;
xdom.NodeSet = function (nodeSet = []) {
    if (!(this instanceof xdom.NodeSet)) return new xdom.NodeSet(nodeSet);
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
            //            target.remove(); //originalRemoveAttribute.apply(ownerElement, [attribute_name]);
            //            //ownerElement.removeAttribute(attribute_name, refresh);
            //        }
            //    } else {
            //        refresh = [refresh, true].coalesce();
            //        target.remove(); //originalRemove.apply(target, arguments);
            //        //target.remove(refresh);
            //        //target.parentNode.removeChild(target); //Se cambió el método por remove para que sea responsivo
            //    }
            //}
            ////stores.map(store => store.render(refresh));
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'setAttribute', {
        value: async function (attribute, value, refresh) {
            attribute = attribute.replace(/^@/, "");
            nodeSet.map((target) => {
                if (target instanceof Element || target.nodeType == 1) {
                    target.setAttribute(undefined, attribute, value, refresh);
                }
            });
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'setAttributeNS', {
        value: async function (attribute, value, refresh) {
            attribute = attribute.replace(/^@/, "");
            nodeSet.map((target) => {
                if (target instanceof Element || target.nodeType == 1) {
                    target.setAttributeNS(undefined, attribute, value, refresh);
                }
            });
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'getAttribute', {
        value: function (attribute) {
            attribute = attribute.replace(/^@/, "");
            return nodeSet.reduce((arr, item) => { arr.push(item.getAttribute(attribute)); return arr; }, []);
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'highlight', {
        value: function () {
            nodeSet.map(node => { [...document.querySelectorAll(`#${node.getAttribute("x:id")},[xo-source='${node.getAttribute("x:id")}']`)].map(target => target.style.outline = '#f00 solid 2px') })
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'setAttributes', {
        value: async function (delay) {
            if (!isNaN(parseInt(delay))) {
                await xdom.delay(delay);
            }
            return new Promise((resolve, reject) => {
                nodeSet.map(target => {
                    if (target instanceof Element || target.nodeType == 1) {
                        target.setAttributes.apply(target, arguments).then(() => resolve(true));
                    }
                });
            });
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'removeAttribute', {
        value: function (attribute, refresh, delay) {
            attribute = attribute.replace(/^@/, "");
            var stores = [];
            nodeSet.map((target) => {
                if (target.ownerDocument.store && !stores.find(store => store === target.ownerDocument.store)) {
                    stores.push(target.ownerDocument.store)
                }
                if (target instanceof Element || target.nodeType == 1) {
                    refresh = [refresh, true].coalesce();
                    originalRemoveAttribute.apply(target, [attribute]);
                }
            });
            stores.map(store => store.render(refresh));
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'appendBefore', {
        value: function () {
            nodeSet.map(target => {
                if (target instanceof Element || target.nodeType == 1) {
                    target.appendBefore.apply(target, arguments);
                }
            });
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'appendAfter', {
        value: function () {
            nodeSet.map(target => {
                if (target instanceof Element || target.nodeType == 1) {
                    target.appendAfter.apply(target, arguments);
                }
            });
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'textContent', {
        value: function () {
            nodeSet.map(target => {
                if (target instanceof Element || target.nodeType == 1) {
                    target.textContent.apply(target, arguments, false);
                }
            });
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.defineProperty(nodeSet, 'moveTo', {
        value: function () {
            nodeSet.map(target => {
                if (target instanceof Element || target.nodeType == 1) {
                    target.moveTo.apply(target, arguments);
                }
            });
        },
        writable: false, enumerable: false, configurable: false
    });
    Object.setPrototypeOf(nodeSet, this);
    Object.setPrototypeOf(nodeSet, Array.prototype);
    return nodeSet;
}

xdom.xml.createFromActiveX = function () {
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

xdom.xml.getNamespaces = function () {
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

xdom.xml.setNamespaces = function (xml_document, namespaces) {
    Object.entries(namespaces).forEach(ns => {
        xml_document.setAttribute(ns[0], ns[1], false);
    })
    return xml_document;
}

xdom.xml.createNamespaceDeclaration = function () {
    var namespaces = xdom.xml.getNamespaces.apply(this, arguments);
    return xdom.json.join(namespaces, { "separator": " " });
}

xdom.Response = function (response, request) {
    if (!(this instanceof xdom.Response)) return new xdom.Response(response);
    let _original = response.clone();
    let file_name = new URL(response.url).pathname.replace(new RegExp(location.pathname.replace(/[^/]+$/, "")), "");
    if (response.status == 404) {
        if (file_name in xdom.library.defaults) {
            response = new Response(xdom.library.defaults[file_name], { headers: { "Content-type": "text/xsl" } })
        } else if (request.options.tag in xdom.stores.defaults) {
            response = new Response(xdom.stores.defaults[request.options.tag], { headers: { "Content-type": "text/xml" } })
        }
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
            let content = response.json ? JSON.stringify(response.json) : response.document.body.innerHTML;
            if (response.ok) {
                if (typeof (to) == 'function') {
                    try {
                        to.apply(to, [content])
                    } catch (e) {
                        if (e.message == 'Illegal invocation') {
                            to.call(window, content);
                        }
                    }
                } else if (to) {
                    to.innerHTML = content;
                } else {
                    xdom.dom.createDialog(content);
                }
            } else {
                xdom.dom.createDialog(content);
            }
        }
    });
    Object.defineProperty(self, 'processBody', {
        value: async function () {
            if (request && request.initiator) {
                window.document.querySelectorAll(`[xo-store="${request.initiator.tag}"] .working`).forEach(el => el.classList.remove('working'));
                request.initiator.state.loading = undefined;
            }

            let body = undefined;
            let contentType = (response.headers.get('Content-Type') || '');
            var responseText;
            if (contentType.toLowerCase().indexOf("iso-8859-1") != -1) {
                await response.arrayBuffer().then(buffer => {
                    let decoder = new TextDecoder("iso-8859-1");
                    let text = decoder.decode(buffer);
                    responseText = text;
                }).catch(error => Promise.reject(error));
            } else {
                if (contentType.toLowerCase().indexOf("manifest") != -1) {
                    //await response.json().then(json => body = json);
                    await response.text().then(text => body = text);
                    responseText = body;
                } else if (contentType.toLowerCase().indexOf("json") != -1) {
                    await response.json().then(json => body = json);
                    responseText = JSON.stringify(body);
                } else {
                    await response.text().then(text => body = text);
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
                    if (_body_type) {
                        return _body_type;
                    } else if (response.headers.get('Content-Type').toLowerCase().indexOf("html") != -1) {
                        return "html";
                    } else if ((response.headers.get('Content-Type').toLowerCase().indexOf("json") != -1 || response.headers.get('Content-Type').toLowerCase().indexOf("manifest") != -1) && xdom.json.isValid(xdom.json.tryParse(responseText))) {
                        return "json";
                    } else if ((response.headers.get('Content-Type').toLowerCase().indexOf("xml") != -1 || response.headers.get('Content-Type').toLowerCase().indexOf("xsl") != -1 || contentType.toLowerCase().indexOf("<?xml ") != -1) && xdom.xml.isValid(xdom.xml.tryParse(responseText))) {
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
                    Object.defineProperty(response, 'html', {
                        get: function () {
                            return body;
                        }
                    });
                    break;
                case "xml":
                    body = xdom.xml.createDocument(responseText);
                    Object.defineProperty(response, 'xml', {
                        get: function () {
                            return body;
                        }
                    });
                    break;
                case "json":
                case "manifest":
                    body = xdom.json.tryParse(responseText);
                    Object.defineProperty(response, 'json', {
                        get: function () {
                            return body;
                        }
                    });
                    if ((request.headers.get('Accept') || '').toLowerCase().indexOf("xml") != -1) {
                        try {
                            body = xdom.json.toXML(body);
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
            }

            if (body instanceof Document) {
                Object.defineProperty(response, 'document', {
                    get: function () {
                        return body;
                    }
                });
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
xdom.Response.prototype = Object.create(Response.prototype);

xdom.Request = function (request, options = {}, payload) {
    if (!(this instanceof xdom.Request)) return new xdom.Request(request, options, payload);
    let url, req, method;
    let self = this;
    let _request = request;
    if (request instanceof Request) {
        req = request;
    } else {
        if (request instanceof URL) {
            url = request;
        } else if (request.constructor == {}.constructor) {
            [, method, url] = (request["url"] || '').match(/^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)?(.*)/)
            url = new URL(url, location.origin + location.pathname.replace(/[^/]+$/, ""));
            params = new URLSearchParams(xdom.json.merge(request["parameters"], request["params"]));
            [...params.entries()].map(([key, value]) => url.searchParams.set(key, value));
        } else {
            [, method, url] = (request || '').match(/^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)?(.*)/)
            url = new URL(url, location.origin + location.pathname.replace(/[^/]+$/, ""));
        }
        let fileExtension = url.pathname.substring(url.pathname.lastIndexOf('.') + 1);
        let headers = new Headers(options["headers"]);
        headers.set("Accept", (headers.get("Accept") || xdom.mimeTypes[fileExtension] || '*/*'));

        options = xdom.json.merge({
            method: (options["method"] || method || payload && 'POST' || 'GET')
            , body: payload
        }, options, {
            headers: headers
        })
        req = new Request(url, options);
    }
    if (req.method == 'POST' && ((event || {}).srcElement || {}).closest) {
        let form = event.srcElement.closest('form');
        if (form && !form.getAttribute('action')) {
            form.setAttributeNS(null, 'action', 'javascript:void(0);'); //Esto corrige comportamiento indeseado en los post cuando el formulario no tiene action
        }
    }

    var srcElement = event && event.target;
    if (srcElement instanceof HTMLElement) {
        let initiator_button = srcElement.closest('button, .btn')
        initiator_button && initiator_button.classList.add("working");
        if (event && event.target && event.target.store && event.target.store.documentElement.tagName == 'x:prompt') { //TODO: Cambiar el método para identificar el initiator
            req.initiator = event && event.target && event.target.store;
        }
    }
    if (req.initiator) {
        req.initiator.state.loading = true;
    }
    Object.defineProperty(self, 'url', {
        get: function () {
            return url;
        }
    })
    Object.defineProperty(self, 'initiator', {
        get: function () {
            return _request.initiator;
        }
    })
    Object.defineProperty(self, 'options', {
        value: options
    })
    Object.defineProperty(self, 'parameters', {
        get: function () {
            return Object.fromEntries(new URL(url).searchParams.entries());
        }
    })
    Object.setPrototypeOf(req, this);
    return req;
}
xdom.Request.prototype = Object.create(Request.prototype);

xdom.fetch = async function (request, options = { rejectCodes: 500 }, payload) {
    if (payload) {
        let pending = [];
        if (payload instanceof XMLDocument) {
            payload.$$("//@*[starts-with(.,'blob:')]").map(node => { pending.push(xdom.server.uploadFile(node)) })
        }
        await Promise.all(pending);
    }
    let req = new xdom.Request(request, options, payload);
    var original_response;
    try {
        original_response = await fetch(req.clone());
    } catch (e) {
        try {
            if (!original_response && req.method == 'POST') {
                const body = await req.clone().text();
                const { cache, credentials, headers, integrity, mode, redirect, referrer } = req;
                const init = { body, cache, credentials, headers, integrity, mode, redirect, referrer };
                original_response = await fetch(req.url, init);
            }
        } catch (e) {
            console.log(e);
            return Promise.reject([e, req, { bodyType: 'text' }]);
        }
    }
    let response = new xdom.Response(original_response, req);
    let document = await response.processBody();

    if (document instanceof Document) {
        let url = req.url;
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

    if (!response.ok && (typeof (options.rejectCodes) == 'number' && response.status >= options.rejectCodes || options.rejectCodes instanceof Array && options.rejectCodes.includes(response.status))) {
        return Promise.reject(response);
    } else if (response.status == 401) {
        xdom.session.status = "unauthorized";
    }
    if (response.status == 204) {
        return Promise.reject(response);
    } else if ([409].includes(response.status) && (req.headers.get("Accept") || "").indexOf('xml') != -1 && !(document || {}).documentElement) {
        xdom.dom.createDialog(xdom.xml.createDocument(`<x:message xmlns:x="http://panax.io/xdom" x:id="xhr_message_${Math.random()}" type="server_error"/>`));
    } else if (
        (req.headers.get("Accept") || "").indexOf("*/*") != -1 ||
        xdom.mimeTypes[response.bodyType] == req.headers.get("Accept") ||
        (req.headers.get("Accept") || "").replace("text/plain", "text").indexOf(document.type) != -1 ||
        (req.headers.get("Accept") || "").replace("text/plain", "text").indexOf(response.bodyType) != -1) {
        return Promise.resolve(response);
    } else if (response.bodyType == 'html' && document instanceof DocumentFragment) {
        xdom.dom.createDialog(document);
    }

    return Promise.reject(response);
}

xdom.fetch.from = async function () {
    let response = await xdom.fetch.apply(this, arguments);
    return response.body;
}

xdom.fetch.xml = async function (url, options = { rejectCodes: 500 }, on_success) {
    options["headers"] = (options["headers"] || {});
    options["headers"]["Accept"] = (options["headers"]["Accept"] || "text/xml, text/xsl")

    let response = await xdom.fetch(url, options, on_success);
    let return_value = response.document;
    //if (!return_value.documentElement && response.headers.get('Content-Type').toLowerCase().indexOf("json") != -1) {
    //    return_value = xdom.json.toXML(return_value.documentElement);
    //}
    return_value.documentElement && return_value.documentElement.selectNodes("xsl:import|xsl:include").map(async node => {
        let href = node.getAttribute("href");
        if (!href.match(/^\//)) {
            let new_href = new URL(href, response.url).pathname.replace(new RegExp(location.pathname.replace(/[^/]+$/, "")), "");
            node.setAttributeNS(null, "href", new_href);
        }
    });
    let imports = return_value.documentElement && return_value.documentElement.selectNodes("xsl:import|xsl:include").reduce((arr, item) => { arr.push(item.getAttribute("href")); return arr; }, []) || [];
    if (imports.length) {
        await xdom.library.load(imports);
    }
    return return_value;
}

xdom.fetch.json = async function (url, options = { rejectCodes: 400 }, on_success) {
    options["headers"] = (options["headers"] || {});
    options["headers"]["Accept"] = (options["headers"]["Accept"] || "application/json")
    let return_value = await xdom.fetch(url, options, on_success).then(response => response.json);
    return return_value;
}

xdom.xml.fromString = function (xmlString) {
    if (window.DOMParser) {
        parser = new DOMParser();
        xmlDoc = parser.parseFromString(xmlString, "text/xml");
    }
    else // Internet Explorer
    {
        xmlDoc = xdom.xml.createDocument();
        xmlDoc.loadXML(xmlString);
        xmlDoc.setProperty("SelectionLanguage", "XPath");
    }
    return xmlDoc
}

xdom.xml.normalizeNamespaces = function (xml) {
    if (!xml || xml instanceof HTMLDocument || xml instanceof HTMLElement) return xml;
    var xsl_transform = xdom.xml.createDocument(`
    <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
      <xsl:output method="xml" indent="no" omit-xml-declaration="yes"/>
      <xsl:template match="@* | * | text() | processing-instruction() | comment()" priority="-1">
        <xsl:copy>
          <xsl:copy-of select="//namespace::*"/>
          <xsl:copy-of select="@*|*|text()"/>
        </xsl:copy>
      </xsl:template>
    </xsl:stylesheet>
    `, 'text/xml');
    if (navigator.userAgent.indexOf("Firefox") != -1) {
        xsl_transform.selectNodes("//xsl:copy-of[contains(@select,'namespace::')]").remove();
    }
    return xml.transform(xsl_transform);
}

xdom.xml.transform = function (xml, xsl, target) {
    var xmlDoc;
    var result = undefined;
    if (xml && !xsl && ((arguments || {}).callee || {}).caller != xdom.xml.transform) {
        for (let stylesheet of xml.stylesheets) {
            xml = xml.transform(stylesheet.document || stylesheet.href);
        }
    }
    if (typeof (xsl) == "string") {
        if (!(xsl in xdom.library)) {
            //xdom.library.load(xsl, function () { }, { async: false });
            if (xdom.browser.isIphone()) {
                (async () => {
                    xdom.library[xsl] = await xdom.fetch.xml(xsl);
                    xsl = xdom.library[xsl];
                })();
            } else {
                xsl = xdom.xml.createDocument(`                          
                <xsl:stylesheet version="1.0"                        
                    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                    <xsl:import href="${xsl}" />
                </xsl:stylesheet>`);
            }
        } else {
            xsl = xdom.library[xsl];
        }
    }
    if (!(xml && xsl)) {
        return xml;//false;
    }
    var original_doc = xml;
    if (xml instanceof xdom.Store) {
        xml = xml.document;
    }
    if (xsl instanceof xdom.Store) {
        xsl = xsl.document;
    }
    if (!(typeof (xsl.selectSingleNode) != 'undefined' && xsl.selectSingleNode('xsl:*'))) {
        throw ("XSL document is empty or invalid");
        return xml;//null;
    }
    if (typeof (xml) == "string") {
        xml = xdom.xml.createDocument(xml);
    }
    if (!xml.selectSingleNode("self::*|*|comment()") && xml.createComment) {
        xml.appendChild(xml.createComment("empty"))
    }
    if (window.ActiveXObject || "ActiveXObject" in window) {
        var xslt = new ActiveXObject("Msxml2.XSLTemplate.3.0");
        var xslDoc = new ActiveXObject("Msxml2.FreeThreadedDOMDocument.3.0");
        var xslProc;
        xslDoc.async = false;
        xslDoc.loadXML(xsl.toString());
        xslDoc.setProperty("SelectionLanguage", "XPath");
        var namespaces = xdom.xml.createNamespaceDeclaration(xml, xsl);
        xslDoc.setProperty("SelectionNamespaces", namespaces);
        if (xslDoc.parseError.errorCode != 0) {
            var myErr = xslDoc.parseError;
            throw ("xsl: You have an error in transform: " + myErr.reason);
            return null;
        } else {
            if (target) {
                xmlDoc = target
            } else {
                xmlDoc = new ActiveXObject("Msxml2.DOMDocument.3.0");
                xmlDoc.async = false;
                xmlDoc.setProperty("SelectionLanguage", "XPath");
                xmlDoc.setProperty("SelectionNamespaces", namespaces);
            }
            if (typeof (xml.transformNodeToObject) != "undefined") {
                //xml.loadXML(xml.xml)
                //xmlDoc = xml//xdom.xml.createDocument(xml);//xml.selectSingleNode(".");
            } else {
                xmlDoc.loadXML(xml.toString());
                if (xmlDoc.parseError.errorCode != 0) {
                    var myErr = xmlDoc.parseError;
                    throw ("doc: You have an error in transform: " + myErr.reason);
                    return null;
                } /*else {
                xslProc = xslt.createProcessor();
                xslProc.input = xmlDoc;
                xslProc.addParameter("param1", "Hello");
                xslProc.render();
                console.log(xslProc.output);
            }*/
            }
        }
        //result = xdom.xml.createDocument(xmlDoc.transformNode(xslDoc))
        try {
            xml.transformNodeToObject(xslDoc, xmlDoc);
        } catch (e) {
            //xdom.xhr.upload(xml.toString());
            //xdom.xhr.upload(xslDoc.toString());
            console.error("xdom.xml.transform: " + xmlDoc.parseError.reason);
            return xml;
        }
        result = xmlDoc;
    }
    else if (document.implementation && document.implementation.createDocument) {
        var xsltProcessor = new XSLTProcessor();
        //target = (target || xml.ownerDocument)
        //if (target) {
        //    result = xsltProcessor.transformToFragment(xml, xml.ownerDocument).firstElementChild;
        //} else {
        try {
            if (navigator.userAgent.indexOf("Firefox") != -1) {
                var invalid_node = xsl.selectSingleNode("//*[contains(@select,'namespace::')]");
                if (invalid_node) {
                    console.warn('There is an unsupported xpath in then file');
                }
            }
            if (navigator.userAgent.indexOf("iPhone") != -1 || xdom.debug["xdom.xml.consolidate"]) {
                xsl = xdom.xml.consolidate(xsl); //Corregir casos cuando tiene apply-imports
            }

            //////if (xsl.url) {
            ////xsl.documentElement.selectNodes("xsl:import|xsl:include").map(node => {
            ////    let href = node.getAttribute("href");
            ////    //if (!href.match(/^\//)) {
            ////    //let new_href = new URL(href, xsl.url);
            ////    //node.setAttributeNS(null, "href", new_href.pathname);
            ////    //node.setAttributeNS(null, "href", href);
            ////    if (xdom.library[href]) {
            ////        //xsltProcessor.importStylesheet(xdom.library[href]);
            ////        let fragment = document.createDocumentFragment();
            ////        fragment.append(xml.createComment(` ========== Imported from "${href}" ==========> `));
            ////        let library = xdom.library[href].cloneNode(true);
            ////        fragment.append(...library.documentElement.childNodes);
            ////        fragment.append(xml.createComment(` <========== Imported from "${href}" ========== `));
            ////        node.replace(fragment);

            ////        var xsl_remove_duplicated = xdom.xml.createDocument(`
            ////                <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
            ////                    <xsl:output method="xml" indent="no" omit-xml-declaration="yes"/>
            ////                    <xsl:key name="node_by_name" use="@name" match="/*/xsl:*"/>
            ////                    <xsl:key name="node_by_name" use="@method" match="/*/xsl:output"/>
            ////                    <xsl:template match="@* | * | text() | processing-instruction() | comment()" priority="-1">
            ////                        <xsl:if test="count(key('node_by_name',concat(@name,@method))[last()]|.)&lt;=1">
            ////                            <xsl:copy-of select="."/>
            ////                        </xsl:if>
            ////                    </xsl:template>
            ////                    <xsl:template match="/*">                                
            ////                    <xsl:copy>
            ////                      <xsl:copy-of select="@*"/>
            ////                      <xsl:apply-templates/>
            ////                    </xsl:copy>
            ////                  </xsl:template>
            ////                </xsl:stylesheet>
            ////                `, 'text/xml');
            ////        xsl = xdom.xml.transform(xsl, xsl_remove_duplicated);
            ////    }
            ////    //}
            ////});
            //////}
            xsltProcessor.importStylesheet(xsl);
            xsl.selectNodes(`//xsl:stylesheet/xsl:param[starts-with(@name,'js:')]`).filter(param => param.textContent).map(param => {
                try {
                    xsltProcessor.setParameter(null, param.getAttribute("name"), eval(param.textContent))
                } catch (e) {
                    //xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                    console.error(e.message);
                    xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                }
            });
            xsl.selectNodes(`//xsl:stylesheet/xsl:param[starts-with(@name,'session:')]`).map(param => {
                try {
                    let param_name = param.getAttribute("name").split(":").pop();
                    if (!(param_name in xdom.session)) xdom.session[param_name] = [eval(`(${param.textContent !== '' ? param.textContent : undefined})`), ''].coalesce();
                    let session_value = xdom.session.getKey(param.getAttribute("name").split(/:/).pop());
                    if (session_value !== undefined) {
                        xsltProcessor.setParameter(null, param.getAttribute("name"), session_value);
                    }
                } catch (e) {
                    //xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                    console.error(e.message);
                }
            });
            xsl.selectNodes(`//xsl:stylesheet/xsl:param[starts-with(@name,'state:')]`).map(param => {
                try {
                    let state_value = xdom.stores.active.state[param.getAttribute("name").split(/:/).pop()];
                    if (state_value !== undefined) {
                        xsltProcessor.setParameter(null, param.getAttribute("name"), state_value);
                    }
                } catch (e) {
                    //xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                    console.error(e.message);
                }
            });

            ////if (!xml.documentElement) {
            ////    xml.appendChild(xdom.xml.createDocument(`<x:empty xmlns:x="http://panax.io/xdom"/>`).documentElement)
            ////}
            if (xsl.selectSingleNode('//xsl:param[@name="debug:timer" and text()="true"]')) {
                console.time();
            }
            if (xsl.documentElement.getAttribute("xmlns") && !(xsl.selectSingleNode('//xsl:output[@method="html"]')) /*xdom.browser.isIOS()*/) {// && ((result || {}).documentElement || {}).namespaceURI == "http://www.w3.org/1999/xhtml" ) {
                let transformed = xsltProcessor.transformToFragment(xml, document);
                var newDoc;
                //if (transformed.children.length && transformed.firstElementChild.namespaceURI == "http://www.w3.org/1999/xhtml") {
                //newDoc = document.implementation.createDocument("http://www.w3.org/1999/xhtml", "html", null);
                //} else {
                //}

                if (transformed && transformed.children.length > 1) {
                    newDoc = document.implementation.createDocument("http://www.mozilla.org/TransforMiix", "result", null);
                    [...transformed.children].map(el => newDoc.documentElement.append(el))
                } else {
                    newDoc = document.implementation.createDocument("http://www.w3.org/XML/1998/namespace", "", null);
                    if (transformed && transformed.firstElementChild) {
                        newDoc.append(transformed.firstElementChild)
                    }
                }
                result = newDoc;
            } else {
                result = xsltProcessor.transformToDocument(xml);
            }
            if (xsl.selectSingleNode('//xsl:param[@name="debug:timer" and text()="true"]')) {
                console.timeEnd();
            }
        } catch (e) {
            let default_document = xdom.library.defaults[(xsl.selectSingleNode("//xsl:import") || document.createElement('p')).getAttribute("href")];
            if (default_document && arguments.callee.caller != xdom.xml.transform) {
                result = xml.transform(default_document);
            } else if (!xml.documentElement) {
                return xml;
            } else {
                console.error("xdom.xml.transform: " + (e.message || e.name)); //TODO: No está entrando en esta parte, por ejemplo cuando hay un error 404. net::ERR_ABORTED 404 (Not Found)
                return xml;
            }
        }
        //}
        if (!result) {
            if (((arguments || {}).callee || {}).caller != xdom.xml.transform && xsl.selectSingleNode('//xsl:import[@href="login.xslt"]')) {
                result = xdom.xml.transform(xml, xdom.library.defaults["login.xslt"]);
            } else if (((arguments || {}).callee || {}).caller != xdom.xml.transform && xsl.selectSingleNode('//xsl:import[@href="shell.xslt"]')) {
                result = xdom.xml.transform(xml, xdom.library.defaults["shell.xslt"]);
            } else if (!xml.documentElement) {
                return xml;
            } else {
                throw (xdom.messages.transform_exception || "There must be a problem with the transformation file. A misplaced attribute, maybe?"); //Podría ser un atributo generado en un lugar prohibido. Se puede enviar al servidor y aplicar ahí la transformación //TODO: Hacer una transformación del XSLT para identificar los problemas comúnes.
                result = xml;
            }
        }
        else if (typeof (result.selectSingleNode) == "undefined" && result.documentElement) {
            result = xdom.xml.createDocument(result.documentElement);
        }
        [...result.querySelectorAll('parsererror div')].map(message => {
            if (String(message.textContent).match(/prefix|prefijo/)) {
                var prefix = (message.textContent).match(/(?:prefix|prefijo)\s+([^\s]+\b)/).pop();
                if (!xdom.xml.namespaces[prefix]) {
                    var message = xdom.data.createMessage(message.textContent.match("(error [^:]+):(.+)").pop());
                    xml.documentElement.appendChild(message.documentElement);
                    return xml;
                }
                (xml.documentElement || xml).setAttributeNS('http://www.w3.org/2000/xmlns/', "xmlns:" + prefix, xdom.xml.namespaces[prefix]);
                result = xml.transform(xsl, target);
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
        if (((arguments || {}).callee || {}).caller != xdom.xml.transform) {
            window.top.dispatchEvent(new xdom.listener.Event('xmlTransformed', { original: xml, transformed: result }));
        }
    } catch (e) { }
    return result
}

xdom.xml.consolidate = function (xsl) {
    var imports = xsl.documentElement.selectNodes("xsl:import|xsl:include");
    var processed = {};
    while (imports.length) {
        imports.map(node => {
            let href = node.getAttribute("href");
            if (xsl.selectSingleNode(`//comment()[contains(.,'=== Imported from "${href}" ===')]`)) {
                node.remove();
            } else if (xdom.library[href]) {
                //xsltProcessor.importStylesheet(xdom.library[href]);
                let fragment = document.createDocumentFragment();
                fragment.append(xsl.createComment(` === Imported from "${href}" ===>>>>>>>>>>>>>>> `));
                let library = xdom.library[href].cloneNode(true);
                Object.entries(xdom.json.difference(xdom.xml.getNamespaces(library), xdom.xml.getNamespaces(xsl))).map(([prefix, namespace]) => {
                    xsl.documentElement.setAttributeNS('http://www.w3.org/2000/xmlns/', `xmlns:${prefix}`, namespace)
                });
                fragment.append(...library.documentElement.childNodes);
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
        xsltProcessor.importStylesheet(xdom.xml.createDocument(`
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

        imports = xsl.documentElement.selectNodes("xsl:import|xsl:include").filter(node => {
            return !(processed[node.getAttribute("href")]) || xsl.selectSingleNode(`//comment()[contains(.,'=== Imported from "${node.getAttribute("href")}" ===')]`);
        });
    }
    return xsl;
}

xdom.xml.createDocument = function (xml, options = {}) {
    var result = undefined;
    var sXML = (xml && xml.document || xml || '').toString();
    if (sXML.indexOf('<<<<<<< ') != -1) {
        throw ("Possible unresolved GIT conflict on file.");
    }
    result = new DOMParser();
    if (!sXML) {
        result = document.implementation.createDocument("http://www.w3.org/XML/1998/namespace", "", null);
    } else {
        if (xml.namespaceURI && xml.namespaceURI.indexOf("http://www.w3.org") == 0) {
            result = result.parseFromString(sXML, "text/html");
        } else {
            result = result.parseFromString(sXML, "text/xml");
        }
        if (sXML && result.getElementsByTagName && (result.getElementsByTagName('parsererror').length || 0) > 0) {
            [...result.querySelectorAll('parsererror div')].map(message => {
                if (String(message.textContent).match(/prefix|prefijo/)) {
                    var prefix = (message.textContent).match(/(?:prefix|prefijo)\s+([^\s]+\b)/).pop();
                    if (!xdom.xml.namespaces[prefix]) {
                        var message = xdom.data.createMessage(message.textContent.match("(error [^:]+):(.+)").pop());
                        //xml.documentElement.appendChild(message.documentElement);
                        return message;
                    }
                    //(xml.documentElement || xml).setAttributeNS('http://www.w3.org/2000/xmlns/', "xmlns:" + prefix, xdom.xml.namespaces[prefix]);
                    sXML = sXML.replace(new RegExp(`\\b${prefix}:`), `xmlns:${prefix}="${xdom.xml.namespaces[prefix]}" $&`)
                    result = xdom.xml.createDocument(sXML);
                    return result;
                } else if (message.closest("html") && String(message.textContent).match(/Extra content at the end of the document/)) {
                    message.closest("html").remove();
                    //result = document.implementation.createDocument("http://www.w3.org/XML/1998/namespace", "", null);
                } else if (message.closest("html")) {
                    if (options["silent"] !== true) {
                        xdom.dom.createDialog(message.closest("html"));
                    }
                    throw (message.textContent);
                } else {
                    var message = xdom.data.createMessage(message.textContent.match("(error [^:]+):(.+)").pop());
                    return message;
                }
            });
        }
    }

    var _manifest_filter_xpath = function (xpath) {
        try {
            return !!result.selectSingleNode(xpath);
        } catch (e) {
            return false;
        }
    }

    if (result.documentElement && !["http://www.w3.org/1999/xhtml", "http://www.w3.org/1999/XSL/Transform"].includes(result.documentElement.namespaceURI)) {
        Object.entries((xdom.manifest.modules || {})).filter(([key, value]) => key.match(/^[^#]/) && value["transforms"] && _manifest_filter_xpath(key)).reduce((stylesheet, [key, value]) => { return value["transforms"] }, []).map(stylesheet => {
            result.addStylesheet(stylesheet);
        });
    }
    return result;
}

xdom.xml.isValid = function (input) {
    return (input instanceof XMLDocument);
}

xdom.xml.tryParse = function (input) {
    try {
        let output = xdom.xml.createDocument(input, { silent: true });
        return (output.getElementsByTagName('parsererror') || []).length && input || output;
    } catch (e) {
        return false;
    }
}

xdom.xml.createNode = function (xml_string, notify_error) {
    let doc = xdom.xml.createDocument(xml_string, notify_error)
    return doc.documentElement;
}

xdom.xml.createElement = function (tagName) {
    let { prefix } = xdom.xml.getAttributeParts(tagName);
    let namespace = xdom.stores.active.documentElement.resolveNS(prefix)
    return document.implementation.createDocument(namespace || "", tagName, null).documentElement;
}

xdom.xml.clone = function (source) {
    return xdom.xml.createDocument(source);
}

xdom.xml.fromHTML = function (element) {
    let xhtml = document.implementation.createDocument("http://www.w3.org/1999/xhtml", "", null);
    if (element) {
        xhtml.appendChild(xhtml.importNode(element.documentElement || element, true));
    }
    return xhtml
}

xdom.data.createMessage = function (message_text, message_type) {
    var message = xdom.xml.createDocument('<x:message xmlns:x="http://panax.io/xdom" x:id="xhr_message_' + Math.random() + '" type="' + (message_type || "exception") + '"/>');
    message.documentElement.textContent = message_text;
    console.trace();
    return message;
}

xdom.library.defaults["styles.css"] = xdom.xml.createDocument(`
<style>
iframe {
    display: block;       
    background: #000;
    border: none;         
    height: 100vh;        
    width: 100vw;
    resize: both;
}
</style>`);

xdom.library.defaults["error.xslt"] = xdom.xml.createDocument(`
<xsl:stylesheet version="1.0"                                                                           
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"                                                    
    xmlns="http://www.w3.org/1999/xhtml">                                                               
    <xsl:output method="xml" indent="no" />                                                             
    <xsl:template match="node()">                                                                       
    <div class="jumbotron">                                                                             
        <div class= "container text-center" style="padding-top:30pt; padding-bottom:30pt;">             
            <h2 class="text-center">Parece que la versión que usas ha cambiado o contiene errores en este módulo. Por favor actualiza tus librerías o repórtalo con el administrador.</h2>    
            <br/><button type="button" class="btn btn-primary btn-lg text-center" onclick="xdom.stores.active.library.reload()">Actualizar librerías</button>                               
            <br/><br/><button type="button" class="btn btn-primary btn-lg text-center" onclick="xdom.session.save()">Reportar</button>                                    
        </div>                                                                                          
    </div>                                                                                              
    </xsl:template>                                                                                     
    <xsl:template match="text()|processing-instruction()|comment()"/>                                   
</xsl:stylesheet>`);

xdom.library.defaults["empty.xslt"] = xdom.xml.createDocument(`
<xsl:stylesheet version="1.0"                                                                           
    xmlns:x="http://panax.io/xdom"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"                                                    
    xmlns:js="http://panax.io/xdom/javascript"                                                    
    xmlns="http://www.w3.org/1999/xhtml">                                                               
    <xsl:output method="xml" indent="no" />
    <xsl:param name="js:snapshots"><![CDATA[self.store && self.store.snapshots.length || 0]]></xsl:param>
    <xsl:template match="x:empty">                                                                       
    <div class="jumbotron">                                                                             
        <div class= "container text-center" style="padding-top:30pt; padding-bottom:30pt;">             
            <h2 class="text-center">El documento está vacío.</h2>    
            <xsl:if test="$js:snapshots&gt;0">
            <br/><button type="button" class="btn btn-primary btn-lg text-center" onclick="this.store.undo()">Deshacer último cambio</button>
            </xsl:if>
        </div>                                                                                          
    </div>                                                                                              
    </xsl:template>                                                                                     
    <xsl:template match="text()|comment()|processing-instruction()"/>                                   
</xsl:stylesheet>`);

xdom.library.defaults["shell.xslt"] = xdom.xml.createDocument(`
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

xdom.library.defaults["login.xslt"] = xdom.xml.createDocument(`
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

xdom.library.defaults["loading.xslt"] = xdom.xml.createDocument(`
<xsl:stylesheet version="1.0"                                                                           
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"                                                    
    xmlns="http://www.w3.org/1999/xhtml">                                                               
    <xsl:output method="xml" indent="no" />                                                             
    <xsl:template match="node()">                                                                       
    <div class="loading" onclick="if (this.store &amp;&amp; (this.store.state.submitting || this.store.state.loading)) {{return}}; this.remove(); [this.store &amp;&amp; this.store.stylesheets['loading.xslt']].removeAll();">
      <div class="modal_content-loading">
        <div class="modal-dialog modal-dialog-centered">
          <div class="no-freeze-spinner">
            <div id="no-freeze-spinner">
              <div>
                <i>
                  <img src="./custom/images/favicon.png" class="ring_image"/>
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

xdom.stores.defaults["#login"] = xdom.xml.createDocument(`<?xml-stylesheet type="text/xsl" href="login.xslt" role="login" target="body"?><x:login xmlns:x="http://panax.io/xdom"/> `);

xdom.library.defaults["message.xslt"] = xdom.xml.createDocument(`
<xsl:stylesheet version="1.0" 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:x="http://panax.io/xdom"
  xmlns="http://www.w3.org/1999/xhtml"
  exclude-result-prefixes="xsl x"
>
  <xsl:output method="xml"
     omit-xml-declaration="yes"
     indent="yes" standalone="no"/>

  <!--Mostrar mensajes en la aplicación-->
  <xsl:template match="x:message">
    <div class="{@type}" role="alertdialog">
      <div class="messages" style="z-index: 1090">
        <div class="modal-dialog" role="document" style="padding-top: 160px;">
          <div class="modal-content message-error w-100">
            <div class="modal-header alert">
              <h2 class="modal-title font-weight-bold mt-2" style="margin-left: 4rem !important;">¡Aviso!</h2>
              <button type="button" class="close" data-dismiss="modal" aria-label="Close" onclick="this.closest('[role=\\'alertdialog\\']').remove(); ">
                <!--<img class="gwt-Image mt-2 mr-2" src="./custom/images/circle-x.svg" width="30" height="30"/>-->
                <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" fill="currentColor" class="bi bi-x-circle text-primary_messages" viewBox="0 0 24 24">
                  <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/>
                  <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/>
                </svg>
              </button>
            </div>
            <div class="modal-body ">
              <h4 style="margin-left: 3rem !important;">
                <xsl:value-of select="."/>
              </h4>
            </div>
          </div>
        </div>
      </div>
    </div>
  </xsl:template>
</xsl:stylesheet>`);
xdom.data.default = xdom.xml.createDocument('<?xml-stylesheet type="text/xsl" href="shell.xslt" role="shell" target="body"?><shell:shell xmlns:x="http://panax.io/xdom" xmlns:shell="http://panax.io/shell" xmlns:state="http://panax.io/state" xmlns:source="http://panax.io/fetch/request" x:id="shell" x:hash=""></shell:shell>');

xdom.stores.defaults["#shell"] = xdom.xml.createDocument('<?xml-stylesheet type="text/xsl" href="shell.xslt" role="shell" target="body"?><shell:shell xmlns:x="http://panax.io/xdom" xmlns:shell="http://panax.io/shell" xmlns:state="http://panax.io/state" xmlns:source="http://panax.io/fetch/request" x:id="shell" x:hash=""></shell:shell>');

xdom.stores.defaults["#settings"] = xdom.xml.createDocument('<?xml-stylesheet type="text/xsl" href="widget.xslt" role="settings" target="@#shell @#settings"?><shell:settings xmlns:shell="http://panax.io/shell"/>');
xdom.init = async function () {
    this.init.initializing = this.init.initializing || new Promise(async (resolve) => {
        if (history.state) delete history.state.active;
        let manifest = await xdom.fetch.json('.manifest', { headers: { Accept: "*/*" } });
        xdom.manifest = new xdom.Manifest(manifest.merge(xdom.manifest));
        xdom.modernize();
        await xdom.library.load(xdom.manifest.transforms);
        await xdom.stores.restore();  //TODO: Ver si se puede poner después de loading (Tener cuidado, pues ese render puede hacer fetch y sobreescribir el store actual)
        xdom.session.cache_name = typeof (caches) != 'undefined' && (await caches.keys()).find(cache => cache.match(new RegExp(`^${location.hostname}_`))) || "";
        xdom.dom.refreshTitle();
        this.init.status = 'initialized';
        //loading = await xdom.library["loading.xslt"].render();
        xdom.session.checkStatus();
        //let [current_status, current_user] = [await xdom.session.status, await xdom.session.user_login];
        //if (current_status != 'authorized' && current_user === undefined) {
        //    xdom.session.login();
        //}
        xdom.stores.active.render();
        //    return resolve(loading);
        //}).then(loading => {
        //    //loading.documentElement.remove();
    }).finally(() => {
        this.init.initializing = undefined;
    });
    return this.init.initializing;
}

xdom.data.getTransformations = function (xml_document) {
    var xml_document = (xml_document || xdom.stores.active || {});
    if (typeof (xml_document.selectSingleNode) == 'undefined') return {};
    if (!xml_document.selectSingleNode("*")) return {};
    var library = {};
    if (typeof (xml_document.setProperty) != "undefined") {
        var current_namespaces = xdom.xml.getNamespaces(xml_document.getProperty("SelectionNamespaces"));
        if (!current_namespaces["x"]) {
            current_namespaces["x"] = "http://panax.io/xdom";
            xml_document.setProperty("SelectionNamespaces", xdom.json.join(current_namespaces, { "separator": " " }));
        }
    }
    var transform_collection = xml_document.selectNodes('.//@*[local-name()="transforms" and contains(namespace-uri(), "http://panax.io/xdom") or namespace-uri()="http://panax.io/transforms"]');
    if (transform_collection.length) {
        for (let s = 0; s < transform_collection.length; ++s) {
            var transforms = transform_collection[s].value.split(/\s*;+\s*/)
            for (let t = 0; t < transforms.length; ++t) {
                if (!transforms[t]) {
                    continue;
                }
                library[transforms[t]] = undefined; //xdom.library[transforms[t]];
            }
        }
    }
    //else {
    //    var file_name = ((window.location.pathname.match(/[^\/]+$/g) || []).join('').split(/\.[^\.]+$/).join('') || "default") + ".xslt";
    //    library[file_name] = xdom.library[file_name];
    //}
    var stylesheets = xml_document.selectNodes("processing-instruction('xml-stylesheet')");
    for (let s = 0; s < stylesheets.length; ++s) {
        stylesheet = JSON.parse('{' + (stylesheets[s].data.match(/(\w+)=(["'])([^\2]+?)\2/ig) || []).join(", ").replace(/(\w+)=(["'])([^\2]+?)\2/ig, '"$1":$2$3$2') + '}');
        if ((stylesheet.type || '').indexOf('xsl') != -1) {
            library[stylesheet.href] = undefined; //xdom.library[stylesheet.href];
        }
    }
    return library;
}

xdom.xml.Empty = function () {
    if (!(this instanceof xdom.xml.Empty)) return new xdom.xml.Empty();
    return xdom.xml.createDocument();
}

xdom.xml.safeEntities = {
    "<": "&lt;"
}

xdom.xml.encodeEntities = function (text) {
    new_text = text;
    new_text = new_text.replace(/</g, xdom.xml.safeEntities["<"]);
    return new_text;
}

xdom.dom.findClosestElementWithAttribute = function (element, attribute) {
    if (!element) return element;
    if (element.getAttribute(attribute)) {
        return element;
    } else if (element.parentElement) {
        return xdom.dom.findClosestElementWithAttribute(element.parentElement, attribute);
    } else {
        return undefined;
    }
}

xdom.dom.findClosestElementWithTagName = function (element, tagName) {
    if (!element) return element;
    if ((element.tagName || "").toUpperCase() == tagName.toUpperCase()) {
        return element;
    } else if (element.parentElement) {
        return xdom.dom.findClosestElementWithTagName(element.parentElement, tagName);
    } else {
        return undefined;
    }
}

xdom.dom.findClosestElementWithClassName = function (element, className) {
    if (!element) return element;
    var regex = new RegExp('\b(' + className + ')\b', "ig");

    if (element.classList && element.classList.contains && element.classList.contains(className)) {
        return element;
    } else if (element.parentElement) {
        return xdom.dom.findClosestElementWithClassName(element.parentElement, className);
    } else {
        return undefined;
    }
}

xdom.dom.findClosestElementWithId = function (element) {
    if (!element) return element;
    if (element.id && !element.id.startsWith("_")) {
        return element;
    } else if (element.parentElement) {
        return xdom.dom.findClosestElementWithId(element.parentElement);
    } else {
        return undefined;
    }
}

xdom.delay = function (ms) {
    return ms ? new Promise(resolve => setTimeout(resolve, ms)) : Promise.resolve();
}

xdom.dom.setEncryption = function (dom, encryption) {
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

xdom.dom.refresh = async function () {
    var { forced } = (arguments[0] || {});
    if (forced) {
        xdom.stores.active.library.clear(true);
    }
    return xdom.stores.active.render(forced);
}

Object.defineProperty(xdom.dom.refresh, 'interval', {
    value: function (seconds) {
        var self = this;
        //xdom.session.live.running = live;
        var refresh_rate;
        var _seconds = seconds;
        this.seconds = _seconds;
        if (this.Interval) window.clearInterval(this.Interval);
        if (seconds == 0) {
            window.console.info('Auto refresh stopped.');
        } else {
            window.console.info(`Starts refresh of ${xdom.stores.active.tag} for every ${seconds} seconds.`);
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
            await xdom.dom.refresh({ forced: true });
        };

        self.Interval = setInterval(function () {
            refresh.apply(self)
        }, refresh_rate);
    },
    writable: false, enumerable: false, configurable: false
});

Object.defineProperty(xdom.dom.refresh, 'stop', {
    value: function () {
        xdom.dom.refresh.seconds = undefined;
        if (xdom.dom.refresh.Interval) {
            window.clearInterval(xdom.dom.refresh.Interval);
            xdom.dom.refresh.Interval = undefined;
        }
        window.console.info('Auto refresh stopped.');
    },
    writable: false, enumerable: false, configurable: false
});

xdom.dom.clear = function (target) {
    if (target === undefined) {
        target = document.querySelector('body');
    } else if (typeof (target) == "string") {
        target = document.querySelector(target);
    }
    if (!(target && target.innerHTML)) return;
    target.innerHTML = '';
}

xdom.data.getFirstRecord = function (xml) {
    var oXML = xdom.xml.createDocument(xdom.stores.active);
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

xdom.xml.Library = function (object) {
    if (!(this instanceof xdom.xml.Library)) return new xdom.xml.Library(object);
    var _library = (object || {});
    if (!_library.hasOwnProperty('clear')) {
        Object.defineProperty(_library, 'clear', {
            value: function () {
                Object.keys(this).map((key) => {
                    _library[key] = undefined;
                });
            },
            writable: false, enumerable: false, configurable: false
        })
    }
    if (!_library.hasOwnProperty('load')) {
        Object.defineProperty(_library, 'load', {
            value: async function (list) {
                var dependencies_to_load = list || _library.filter((key, value) => !value);
                Object.keys(dependencies_to_load).map((key) => {
                    _library[key] = xdom.fetch.xml(key).then(document => _library[key] = document && document.selectSingleNode && document.selectSingleNode('xsl:stylesheet') && document);
                });
                return Promise.all(Object.values(_library));
            },
            writable: false, enumerable: false, configurable: false
        })
    }
    Object.setPrototypeOf(_library, this);
    return _library;
}

xdom.Store = function (xml) {
    if (!(this instanceof xdom.Store)) return new xdom.Store(xml, arguments[1]);
    var self = this;
    var store = this;
    var _this_arguments = arguments;
    var __document = xdom.xml.createDocument(xml);
    var _undo = [];
    var _redo = [];
    var config = arguments[1] && arguments[1].constructor === {}.constructor && arguments[1];
    var on_complete = !config && arguments[1] && isFunction(arguments[1]) && arguments[1] || config && config["onComplete"];
    var _tag, _hash;
    var _rendering = false;
    var _initiator = config && config["initiator"] || undefined;
    var _library = new Proxy({}, {
        get: function (target, name) {
            return target[name];
        },
        set: function (target, name, value) {
            return target[name] = value //|| target[name]; //Ahora se permite que se asigne undefined para que funcione el método clear.
        }
    });

    if (!_library.hasOwnProperty('clear')) {
        Object.defineProperty(_library, 'clear', {
            value: function (forced = true) {
                Object.keys(this).map((key) => {
                    _library[key] = undefined;
                    if (forced) {
                        xdom.library[key] = undefined;
                        xdom.library.load(key);
                    }
                });
            },
            writable: false, enumerable: false, configurable: false
        })
    }
    if (!_library.hasOwnProperty('load')) {
        Object.defineProperty(_library, 'load', {
            value: async function (list) {
                var dependencies_to_load = list || this.filter((key, value) => !value) || [];
                if (Object.keys(dependencies_to_load).length) {
                    await xdom.library.load(Object.keys(dependencies_to_load));
                }
                await Promise.all(Object.keys(this).reduce((lib, stylesheet) => { xdom.library[stylesheet] instanceof Promise && lib.push(xdom.library[stylesheet]); return lib }, []));
                Object.keys(dependencies_to_load).map((key) => {
                    if (key in xdom.library && xdom.library[key].cloneNode) {
                        this[key] = xdom.library[key].cloneNode(true);/*(this[key] || xdom.fetch.xml(key).then(document => {
                                this[key] = document && document.selectSingleNode && document.selectSingleNode('xsl:stylesheet') && document;
                            }));*/
                    }
                    else {
                        this[key] = xdom.library[key];
                    }
                });
                const loaded_library = await Promise.all(Object.values(this));
                return loaded_library;
            },
            writable: false, enumerable: false, configurable: false
        })
    }
    if (!_library.hasOwnProperty('reload')) {
        Object.defineProperty(_library, 'reload', {
            value: async function (list) {
                _library.clear();
                xdom.library.reset(Object.keys(_library));
                return _library.load();
            },
            writable: false, enumerable: false, configurable: false
        })

        Object.defineProperty(_library.reload, 'interval', {
            value: function (seconds) {
                var self = this;
                //xdom.session.live.running = live;
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
                    window.console.info(`Start refresh of ${xdom.stores.active.tag} for every ${this.seconds} seconds.`);
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
    }

    //for (let endpoint in xdom.manifest.server.endpoints) {
    //    Object.defineProperty(store, endpoint, {
    //        value: async function (...arguments) {
    //            let args = arguments;
    //            if (args.length === 1) {
    //                if (args[0].apply) {
    //                    args = args[0].apply(store, args);
    //                }
    //                if (!args) { console.error(`Method ${endpoint} should be executed with arguments.`) }
    //            }
    //            return xdom.server[endpoint].apply(store, args);
    //        },
    //        writable: true, enumerable: false, configurable: true
    //    });
    //}

    var _isActive = undefined;

    this.state = new Proxy({}, {
        get: function (target, name) {
            return target[name];
        },
        set: function (target, name, value) {
            let refresh;
            if (value && ['function'].includes(typeof (value))) {
                throw ('State value is not valid type');
            }
            let { prefix, name: attribute_name } = xdom.xml.getAttributeParts(name);
            let old_value = target[name]
            //if (old_value != value && !["rendering"].includes(name)) {
            //    refresh = true
            //}
            if (old_value == value) return;
            target[name] = value;
            let state_event = new xdom.listener.Event('stateChanged', { target: store, prefix: prefix, attribute: attribute_name, new: value, old: old_value });
            window.top.dispatchEvent(state_event);
            window.top.dispatchEvent(new xdom.listener.Event(`stateChanged::${name}`, { target: store, new: value, old: old_value }));
            if (!state_event.defaultPrevented) {
                if (refresh) {
                    var name = name, value = value;
                    self.library.load().then(() => {
                        dependencies = self.library;
                        if (Object.values(dependencies).filter(stylesheet => {
                            return !!(stylesheet || window.document.createElement('p')).selectNodes(`//xsl:stylesheet/xsl:param[@name='state:${name}']`).length
                        }).length) {
                            console.log(`Rendering ${self.tag} triggered by state:${name}`);
                            self.render();
                        };
                    });
                }
            }
        }
    })

    __document.status = "loading"

    Object.defineProperty(this, 'library', {
        get: function () {
            _library.merge(this.document.stylesheets.reduce((obj, curr) => { obj[curr.href] = _library[curr.href]; return obj }, {}));
            return _library;
        }/*, set: function (input) {
            _library = xdom.xml.Library(xdom.json.merge(xdom.data.getTransformations(this.document), _library, input));
        }*/
    })

    Object.defineProperty(this, 'tag', {
        get: function () {
            _tag = _tag || this.generateTag.call(this, __document) || xdom.cryptography.generateUUID();
            return '#' + _tag.split(/^#/).pop();
        }
    })

    Object.defineProperty(this, 'hash', {
        get: function () {
            return '#' + Array.prototype.coalesce(_hash, __document.documentElement && Array.prototype.coalesce(__document.documentElement.getAttribute("x:hash"), __document.documentElement.getAttribute("x:tag"), __document.documentElement.localName.toLowerCase()), _tag).split(/^#/).pop();
        },
        set: function (input) {
            if (__document.documentElement) {
                __document.documentElement.setAttributeNS(xdom.xml.namespaces["x"], "x:hash", input);
            }
            _hash = input;
            xdom.state.hash = _hash;
            //xdom.dom.updateHash(_hash);
        }
    });

    Object.defineProperty(this, 'snapshots', {
        get: function () {
            return _undo;
        }
    });

    Object.defineProperty(this, 'findById', {
        value: function (xid) {
            return __document.selectSingleNode('//*[@x:id="' + xid + '"]')
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
                //xdom.dom.refresh({ trigger_bindings: false })
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
                //xdom.dom.refresh({ trigger_bindings: false })
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
                __document = (__document || xdom.xml.createDocument(""));
            }
            //__document.store = this;
            return __document;
        },
        set: function (input) {
            __document = input;
            if (typeof (input) == 'string') {
                __document = xdom.xml.createDocument(input)
            }
            if (__document.documentElement) {
                __document.documentElement.setAttributeNS(xdom.xml.namespaces["x"], "x:tag", (this.tag.replace(/^#/, '') || ""));
                //__document.documentElement.setAttributeNS(xdom.xml.namespaces["state"], "state:refresh", "true");
            }
            xdom.stores[this.tag] = self;
            this.reseed();
            this.initialize();
        }
    })

    Object.defineProperty(this, 'load', {
        value: async function (input) {
            throw ("Load method is deprecated")
        }
    });

    let _render_manager;
    Object.defineProperty(this, 'isRendering', {
        get: function () {
            return (_render_manager instanceof Promise);
        }
    });

    Object.defineProperty(this, 'triggerBindings', {
        value: async function () {
            var context = this;
            if (!(context.isActive)) {
                return;
            }
            if (!(!(((xdom.manifest.server || {}).endpoints || {}).login && !(xdom.session.getKey('status') == 'authorized')) && context && typeof (context.selectSingleNode) != 'undefined' && (context.selectSingleNode('.//@source:*|.//request:*|.//source:*') || context.stylesheets.filter(stylesheet => stylesheet.role == 'binding' || (stylesheet.target || '').match(/^self::./)).length))) {
                return; //*** Revisar si en vez de salir, revisar todo el documento
            }
            //if (!context.selectSingleNode('//@source:*') || context.selectSingleNode('.//@request:*[local-name()!="init"]')) {
            //    return;
            //}
            let new_bindings = 0;
            let bindings = [].concat(
                //[(__document.selectSingleNode("ancestor-or-self::*[@transforms:bindings]/@transforms:bindings") || {}).value],
                context.stylesheets.filter(stylesheet => stylesheet.role == "binding" || (stylesheet.target || '').match(/^self::./) && stylesheet.action == 'replace').map(async function (stylesheet) {
                    if ((await stylesheet.document || window.document.createElement('p')).selectSingleNode('//xsl:copy[not(xsl:apply-templates) and not(comment()="ack:no-apply-templates")]')) {
                        console.warn('In a binding stylesheet a xsl:copy withow a xsl:apply-templates may cause an infinite loop. If missing xsl:apply-templates was intentional, please add an acknowledge comment <!--ack:no-apply-templates-->');
                    };
                    return stylesheet
                })
                , (xdom.manifest.getConfig(context.tag, 'transforms') || []).filter(stylesheet => stylesheet.role == "binding" || (stylesheet.target || '').match(/^self::./)).map(stylesheet => stylesheet.href)
                , ["xdom/databind.xslt"]);
            bindings = [...new Set(bindings)].filter(binding => binding);
            //let original = xdom.xml.clone(context); //Se obtiene el original si se quieren comparar cambios
            if (!__document.documentElement.resolveNS("changed")) {
                __document.documentElement.setAttributeNS(xdom.xml.namespaces["xmlns"], "xmlns:changed", xdom.xml.namespaces["changed"])
            }
            let cloned_document = __document.cloneNode(true);
            cloned_document.store = context;
            let some_changed = false;
            var changed = cloned_document.selectNodes("//@changed:*");
            var stylesheets = [];
            do {
                changed && changed.remove(false);
                for (let binding of bindings) {
                    stylesheet = await binding;
                    if (!stylesheets.find(doc => doc.selectSingleNode(`//xsl:import[@href="${stylesheet.href || stylesheet}"]|//xsl:import[@href="${stylesheet.href || stylesheet}"]|//comment()[contains(.,'=== Imported from "${stylesheet.href || stylesheet}" ===')]`))) {
                        let xsl_doc = await stylesheet.document || context.library[stylesheet] || xdom.library[stylesheet] || await xdom.library.load(stylesheet);
                        stylesheets.push(xsl_doc);

                        if ((stylesheet.target || '').match(/^self::./)) {
                            let i = 0;
                            do {
                                cloned_document.selectNodes("//@binding:changed").remove(false);
                                ++i;
                                cloned_document = cloned_document.transform(xsl_doc);
                            } while (i < 15 && cloned_document.documentElement.selectSingleNode(stylesheet.target) && (!xsl_doc.documentElement.getAttribute('xmlns:binding') || cloned_document.selectSingleNode("//@binding:changed")))
                        } else {
                            cloned_document = cloned_document.transform(xsl_doc);
                        }
                        cloned_document.store = context;
                    }
                }
                changed = cloned_document.selectNodes("//@changed:*");
                some_changed = (some_changed || !!changed.length);
            } while (context && changed.length && ++new_bindings <= 15)
            if (cloned_document.$(`//*[not(@x:id)]`)) {
                cloned_document.reseed();
            }
            //if (some_changed) { //se quita esta validación porque los bindings podrían estar modificando el documento sin marcar un cambio con changed:*
            __document = cloned_document; // context.document = cloned_document; TODO: Revisar si es necesario hacer la asignación por medio de la propiedad .document
            ////}

            ///* Con este código se detectan cambios. Pero es muy costoso*/
            ////let differences = xdom.xml.compare(context, original, true)
            ////differences.selectNodes('//c:change[@c:type!="Node"]').map(change => {
            ////    let changes = change ? [...context.selectSingleNode(`//*[@x:id="${change.getAttribute("x:id")}"]`).attributes].filter(attribute => (attribute.prefix != 'xmlns' && change.getAttribute(attribute.name) != attribute.value)) : [];
            ////    changes.map(attribute => {
            ////        original.store = context.store;
            ////        original.selectSingleNode(`//*[@x:id="${attribute.ownerElement.getAttribute("x:id")}"]`).setAttributeNS(null, attribute.name, attribute.value, false);
            ////    });
            ////})
            //if (!((xdom.manifest.server || {}).endpoints || {}).request) {
            //    return
            //}

            var requests = context.selectNodes(`//*[contains(namespace-uri(),'http://panax.io/fetch/') and not(@state:disabled="true") and not(*)]`)//context.selectNodes('.//source:*[not(@state:disabled="true") and not(*)]|.//request:*[not(@state:disabled="true") and not(*)]');
            if (new_bindings) {
                context.takeSnapshot();
            }
            var tag = context.tag;
            requests = requests.filter(req => !(xdom.data.binding.requests[tag] && xdom.data.binding.requests[tag].hasOwnProperty(req.nodeType == 1 ? req.getAttribute("command") : req.value)));
            if (requests.length) {
                for (let node of requests) {
                    if (!(node.prefix in ((xdom.manifest.server || {}).endpoints || {}))) {
                        console.warn(`Endpoint ${node.prefix} is not configured`)
                        continue;
                    }
                    let node_id = node.getAttribute("x:id");
                    let attribute = node.tagName;
                    let attribute_base_name = (node.baseName || node.localName)
                    let command = node.getAttribute("command");
                    command = command.replace(/^[\s\n]+|[\s\n]+$/g, "");
                    //var request_id = node.getAttribute("x:id") + "::" + command.replace(/^\w+:/, '');
                    //node.setAttributeNS(null, "requesting:" + attribute_base_name, 'true')
                    //if (command && (node && !command.match("{{") /*&& !(xdom.xhr.Requests[node.getAttribute("x:id") + "::" + command])*/ && !node.selectSingleNode(attribute.name + '[@for="' + command + '"]'))) {
                    if (!(command || '').match("{{") && !(xdom.data.binding.requests[tag] && xdom.data.binding.requests[tag][command])) {
                        console.log("Binding " + command);

                        //let [request_with_fields, ...predicate] = command.split(/=>|&filters=/);
                        //let [fields, request] = comnd.match('(?:(.*)~>)?(.+)');
                        let [rest, predicate = ''] = command.split("=>");
                        let [fields, request] = rest.indexOf("~>") != -1 && rest.split("~>") || ["*", rest];
                        //let [, fields, request, predicate = ''] = command.match('(?:(.*)~>|^)?((?:(?<!=>).)+)(?:=>(.+))?$');
                        xdom.data.binding.requests[tag] = (xdom.data.binding.requests[tag] || {});
                        /*TODO: Mover esto a un listener o definir */
                        let root_node = node.prefix.replace(/^request$/, "source") + ":" + attribute_base_name
                        let parameters = (node.getAttribute('source_filters:' + attribute_base_name) || predicate || "");
                        let headers = new Headers({
                            "Cache-Response": (Array.prototype.coalesce(eval(node.getAttribute("cache" + ":" + (attribute_base_name))), eval(node.parentElement.getAttribute("cache" + ":" + (attribute_base_name))), false))
                            , "Accept": content_type.xml
                            , "cache-control": 'force-cache'
                            , "pragram": 'force-cache'
                            , "x-source-tag": tag
                            , "x-original-request": command
                            , "Root-Node": root_node
                            , "X-Detect-Missing-Variables": "false"
                            , "x-data-text": (node.getAttribute('source_text:' + attribute_base_name) || node.getAttribute('dataText') || "")
                            , "x-data-value": (node.getAttribute('source_value:' + attribute_base_name) || node.getAttribute('dataValue') || "")//TODO: quitar dataText y dataValue (sin namespace)
                            , "x-data-fields": (node.getAttribute('source_fields:' + attribute_base_name) || fields || "")
                        })
                        var response_handler = (response) => {
                            //var response_is_message = !!response.documentElement.selectSingleNode('self::x:message');
                            //if (!response_is_message && !response.selectSingleNode(`//${root_node}`)) {
                            //    let new_node = xdom.xml.createDocument(`<${root_node} xmlns:source="http://panax.io/fetch/request"/>`);
                            //    new_node.documentElement.appendChild(response.documentElement);
                            //    response.appendChild(new_node.documentElement);
                            //}
                            ////response.documentElement.setAttributeNS(null, "command", original_request)
                            ////response = xdom.xml.reseed(response);
                            !(response instanceof xdom.Store) && self.selectNodes(`//source:*[@command="${command}"]`).map((targetNode, index, array) => {
                                let new_node = response.cloneNode(true).reseed();
                                let fragment = document.createDocumentFragment();
                                if (response.documentElement.tagName == targetNode.tagName || ["http://www.mozilla.org/TransforMiix"].includes(response.documentElement.namespaceURI)) {
                                    fragment.append(...new_node.documentElement.childNodes);
                                } else {
                                    fragment.append(...new_node.childNodes);
                                }

                                let prev_value = targetNode.parentNode.getAttribute("prev:value");
                                if (response.documentElement.selectSingleNode(`x:r[@value="${prev_value}"]`)) {
                                    targetNode.parentElement.setAttributeNS(null, "value", prev_value)
                                }
                                if (array.length > xdom.data.binding["max_subscribers"]) {
                                    targetNode.parentElement.appendChild(xdom.data.createMessage("Load truncated").documentElement);
                                    console.warn("Too many requests may create a big document. Place binding in a common place.")
                                } else if (fragment.childNodes.length) {
                                    targetNode.append(fragment);
                                    //if (response_is_message) {
                                    //    targetNode.appendChild(response.documentElement);
                                    //} else {
                                    //    let new_node = xdom.xml.createDocument(response);
                                    //    targetNode.selectNodes('@*').map(attr => {
                                    //        new_node.documentElement.setAttributeNS(null, attr.name, attr.value, false)
                                    //    });
                                    //    targetNode.parentElement.replaceChild(new_node.documentElement, targetNode);
                                    //}
                                } else {
                                    targetNode.append(xdom.xml.createNode(`<x:empty xmlns:x="http://panax.io/xdom"/>`));
                                }
                                delete xdom.data.binding.requests[self.tag][command];
                                context.render()
                                //xdom.delay(50).then(() => {
                                //xdom.stores[tag].render(/*true*/);
                                //});
                            });
                        };
                        xdom.data.binding.requests[tag][command] = (xdom.data.binding.requests[tag][command] || xdom.server.request({ command: request, predicate: parameters }, {
                            method: 'GET'
                            , headers: headers
                        }).then(response_handler).catch(response_handler));
                    }
                }
                //xdom.data.binding.updateSources();
            }
        },
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'render', {
        value: async function () {
            let tag = self.tag;
            this.state.rendering = true;
            _render_manager = _render_manager || xdom.delay(1).then(async () => {
                let isActive = self.isActive
                let active_tag = xdom.state.active;
                let active_store = xdom.stores.active;
                if (active_store == self && location.hash != self.hash) {
                    xdom.state.active = tag;
                }
                if (!isActive) {
                    return Promise.reject(`Store ${tag} is not active`);
                }
                //await self.library.load();
                await self.triggerBindings();

                await __document.render();
                return Promise.resolve(self);
            }).then(async () => {
                _render_manager = undefined;
                let targetDocument = ((document.activeElement || {}).contentDocument || document);
                let dom = targetDocument.querySelector(`[xo-store="${tag}"]`)
                window.top.dispatchEvent(new xdom.listener.Event('domLoaded', { target: dom, initiator: this }));
                let active_store = xdom.stores.active;
                if (active_store == self) {
                    self.detectActive(); // xdom.state.detectActive(); //xdom.stores.active.detectActive();
                }
                //if (active_store !== self
                //    && ![...document.querySelectorAll(`[xo-store='${tag}']`)].find(el => el.closest(`[xo-store='${active_store.tag}']`))
                //    && dom.querySelector(`[xo-store='${active_store.tag}']`)) {
                //    await active_store.render(/*true*/);
                //}

                //Esta situación puede darse cuando no se encontró una transformación o esta regresa un documento inválido
                distinct_dependants = {};
                dependants = [...targetDocument.querySelectorAll(`[xo-store="${tag}"] *[xo-store]`)].filter(el => el.getAttribute("xo-store") != tag).map(el => distinct_dependants[el.getAttribute("xo-store")] = el);
                //dependants.filter((el) => !(target.parentElement && target.parentElement.closest(`[xo-store='${el.getAttribute("xo-store")}']`))).map(function (el) {
                //    distinct_dependants[el.getAttribute("xo-store")] = el;
                //}); //Se ignoran los dependientes que sean descendientes de un store que ya existe (para evitar que se cicle);
                let promises = [];
                Object.entries(distinct_dependants).filter(([tag, el]) => (xdom.stores[tag] || {}).isActive && !xdom.stores[tag].isRendering).map(async ([tag, el]) => {
                    let dependant = xdom.stores[tag];
                    el.classList.add("working");
                    if (dependant) {
                        promises.push(dependant.render());
                    }
                });
                Promise.all(promises).then(() => {
                    //xdom.state.restore();
                    if (!this.isRendered) {
                        throw (`Couldn't render store ${store.tag}`);
                    }
                });
                return Promise.resolve(self)
            }).catch((e) => {
                console.warn(e || `Couldn't render store ${store.tag}`);
                return;
            }).finally(async () => {
                _render_manager = undefined;
                this.state.rendering = false;
            });
            return _render_manager;
        },
        writable: true, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'reseed', {
        value: function () {
            var start_date = new Date();
            let data = this.document;
            if (!data.documentElement) return data;
            let xsl = xdom.xml.createDocument(`
    <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:x="http://panax.io/xdom">
	    <xsl:key name="xid" match="*" use="@x:id" />
	    <xsl:template match="*|processing-instruction()|comment()">
		    <xsl:copy>
			    <xsl:copy-of select="@*[not(name()='x:id')]"/>
			    <xsl:apply-templates/>
		    </xsl:copy>
	    </xsl:template>
	    <xsl:template match="*[count(key('xid',@x:id)[1] | .)=1]">
		    <xsl:copy>
			    <xsl:copy-of select="@*"/>
			    <xsl:apply-templates/>
		    </xsl:copy>
	    </xsl:template>
    </xsl:stylesheet>
    `); // removes duplicate xids
            data = data.transform(xsl);
            let xsl_duplicates = xdom.xml.createDocument(`
    <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:x="http://panax.io/xdom">
	    <xsl:key name="xid" match="*" use="@x:id" />
	    <xsl:template match="/">
		    <result>
			    <xsl:apply-templates/>
		    </result>
	    </xsl:template>
	    <xsl:template match="text()|processing-instruction()|comment()"/>
	    <xsl:template match="*"><xsl:apply-templates/></xsl:template>
	    <xsl:template match="*[@x:id and count(key('xid',@x:id)[1] | .)=2]">
		    <xsl:copy>
			    <xsl:copy-of select="@*"/>
		    </xsl:copy>
	    </xsl:template>
    </xsl:stylesheet>
    `);
            let duplicate_id = (data.transform(xsl_duplicates).documentElement || {}).firstChild;
            if (duplicate_id) {
                console.warn("Document contains duplicate ids")
            }
            if (((arguments || {}).callee || {}).caller === this.reseed || !(data && data.selectSingleNode('/*') && data.selectSingleNode('//*[not(@x:id)]'))) {
                return data;
            }

            data = data.reseed();
            __document = data;

            return this.reseed();
        },
        writable: false, enumerable: false, configurable: false
    });

    Object.defineProperty(this, 'initialize', {
        value: async function () {
            //__document.documentElement && Object.entries(xdom.manifest.modules || {}).filter(([key, value]) => !(key.match(/^#/)) && value["transforms"] && _manifest_filter_xpath(key)).reduce((stylesheet, [key, value]) => { return value["transforms"] }, []).map(stylesheet => __document.addStylesheet(stylesheet));

            (xdom.manifest.getConfig(_tag, 'transforms') || []).reverse().filter(transform => !__document.selectSingleNode(`comment()[.="Initialized by ${transform.href}"]`)).map(transform => {
                transform = __document.addStylesheet(transform);
            });
            let inti_stylesheets = __document.stylesheets.filter(stylesheet => stylesheet.role == 'init');
            //await this.library.load(inti_stylesheets.reduce((hrefs, stylesheet) => { hrefs[stylesheet.href] = undefined; return hrefs }, {}));
            await this.library.load();
            inti_stylesheets.map(stylesheet => {
                stylesheet.replaceBy(__document.createComment('Initialized by ' + stylesheet.href));
                let new_document = __document.transform(this.library[stylesheet.href]);
                if ((((new_document.documentElement || {}).namespaceURI || '').indexOf("http://www.w3.org") == -1)) {/*La transformación no debe regresar un html ni otro documento del estándar*/
                    this.document = __document.transform(this.library[stylesheet.href]);
                } else {
                    delete stylesheet["role"];
                    __document.addStylesheet(stylesheet);
                    console.warn("Initial transformation shouldn't yield and html or any other document from the w3 standard.");
                }
            });
            onComplete();
        },
        writable: false, enumerable: false, configurable: false
    });

    onComplete = function () {
        if (['completing', 'ready'].includes(__document.status)) {
            return;
        }
        __document.status = 'completing';
        if (on_complete && on_complete.apply) {
            on_complete.apply(self, _this_arguments);
        };
        __document.status = "ready";
        [__document.stylesheets["loading.xslt"]].removeAll();
    }

    _tag = config && config["tag"] || undefined;
    _hash = config && config["hash"] || undefined;
    if (!__document) throw ("__document is empty");
    if (typeof (__document) == 'string') {
        __document = xdom.xml.createDocument(__document)
    }

    for (let prop of ['$', '$$', 'cloneNode', 'normalizeNamespaces', 'contains', 'documentElement', 'selectSingleNode', 'selectNodes', 'evaluate', 'toClipboard', 'addStylesheet', 'getStylesheet', 'stylesheets', 'getStylesheets', 'createProcessingInstruction', 'firstElementChild', 'insertBefore', 'toString', 'resolveNS', 'xml']) {
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
    __document.store = this;
    window.top.dispatchEvent(new xdom.listener.Event('storeLoaded', { store: this }));
    return this;
}

xdom.Store.prototype.onLoad = function () {
    console.log("Do nothing");
}

Object.defineProperty(xdom.Store.prototype, 'fetch', {
    value: async function (input) {
        _fetch_url = (_fetch_url || input);
        if (!_fetch_url) {
            throw ("No url initialized.")
        }
        let data = await xdom.fetch(_fetch_url).then(response => response.body);
        this.document = data;
        if (xdom.stores.active === this) {
            this.render(/*true*/);
        }
    }
})

Object.defineProperty(xdom.Store.prototype, 'isActive', {
    get: function () {
        return (this.document === xdom.stores.active || xdom.state.activeTags().includes(this.tag) || this.isRendered || !window.document.querySelector("[xo-store]"));
    },
    set: function (input) {
        if (input) {
            history.state.active = this.tag;
        } else {
            delete history.state.active;
        }
    }
});

Object.defineProperty(xdom.Store.prototype, 'isRendered', {
    get: function () {
        return !!document.querySelector(`[xo-store="${this.tag}"]`);
    }
});

Object.defineProperty(xdom.Store.prototype, 'detectActive', {
    value: function () {
        let active_tag = this.tag;
        let active_tags = [...window.document.querySelectorAll(`[xo-store]`)].reduce((new_target, el) => { let tag = el.getAttribute("xo-store"); /*tag != active_tag && */new_target.push(tag); return new_target; }, []);
        active_tags = [...new Set(active_tags)];
        let state_stores = xdom.state.stores;
        state_stores[active_tag] = (state_stores[active_tag] || {})
        state_stores[active_tag]["active"] = active_tags;
        xdom.state.stores = state_stores;
        //xdom.state.activeTags = [...new Set([xdom.state.activeTags(), active_tags].flat())];
        return state_stores[active_tag]["active"];
    }
});

Object.defineProperty(xdom.Store.prototype, 'find', {
    value: function (reference) {
        if (!reference) return null;
        var ref = reference;
        if (typeof (reference) == "string") {
            ref = this.document.selectSingleNode('//*[@x:id="' + reference + '" ]')
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
            return this.document.selectSingleNode('//*[@x:id="' + (ref.ownerElement || document.createElement('p')).getAttribute("x:id") + '"]/@' + ref.name);
        } else {
            return (this.document.selectSingleNode('//*[@x:id="' + (ref.documentElement || ref instanceof Element && ref || document.createElement('p')).getAttribute("x:id") + '"]')); // || xdom.stores.active.selectSingleNode(xdom.xml.getXpath(ref))
        }
    },
    writable: false, enumerable: false, configurable: false
});

xdom.Store.prototype.generateTag = function (document) {
    if (!(document && document.documentElement)) {
        return xdom.cryptography.generateUUID()
    }
    return (document.documentElement && (document.documentElement.getAttribute("x:tag") || document.documentElement.getAttribute("x:id") || document.documentElement.localName.toLowerCase())).split(/^#/).pop();
}

xdom.xml.getAttributeParts = function (attribute) {
    let attribute_name = attribute.split(':', 2);
    var name = attribute_name.pop();
    var prefix = attribute_name.pop();
    return { "prefix": prefix, "name": name }
}

xdom.post = {}
xdom.post.to = async function (request, data, options) {
    return xdom.fetch(request, options, data);
}


xdom.json.toXML = function (json) {
    if (typeof (json) == "string") {
        json = json.replace(/\r\n/g, "")
    } else if (json.constructor == {}.constructor || json.constructor == [].constructor) {
        json = JSON.stringify(json);
    } else {
        throw ("Not a valid json");
    }
    let raw_xson = xdom.xml.createDocument(
        xdom.string.replace(
            xdom.string.replace(
                xdom.string.replace(
                    xdom.string.replace(
                        xdom.string.replace(
                            xdom.string.replace(
                                xdom.string.replace(
                                    xdom.string.replace(
                                        xdom.string.replace(
                                            xdom.string.replace(json, '\\(.)', '<e v="$1"/>', 1)
                                            , '[', '<l>')
                                        , ']', '</l>')
                                    , '{', '<o>')
                                , '}', '</v></o>')
                            , '"([^"]+?)"\\:', '</v><a>$1</a><v>', 1)
                        , '<([^v])></v>', '<$1>', 1)
                    , ',</v><a>', '</v><a>')
                , ',<o>', '<o>')
            , '<l>([^<]+)</l>', '<l><v>$1</v></l>', 1)
    );

    let reformated_xson = raw_xson.transform(xdom.xml.createDocument('<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xi="http://www.w3.org/2001/XMLSchema-instance" xmlns="" xmlns:xson = "http://panax.io/xson"><xsl:template match="/"><xsl:apply-templates/></xsl:template ><xsl:template match="*|text()"><xsl:copy><xsl:copy-of select="@*"/><xsl:apply-templates/></xsl:copy ></xsl:template ><xsl:template match="o"><xsl:copy><xsl:copy-of select="@*"/><xsl:apply-templates select="text()|a"/></xsl:copy ></xsl:template ><xsl:template match="a"><xsl:copy><xsl:element name="n"><xsl:value-of select="text()"/></xsl:element ><xsl:copy-of select="@*" /><xsl:apply-templates select="following-sibling::*[1]/self::v" /></xsl:copy ></xsl:template ></xsl:stylesheet >'));

    let xson = reformated_xson.transform(xdom.xml.createDocument('<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xi="http://www.w3.org/2001/XMLSchema-instance" xmlns="" xmlns:xson = "http://panax.io/xson"><xsl:variable name="invalidChars" select="\'$:/@ \'"></xsl:variable ><xsl:template match="/"><xsl:apply-templates mode="raw-to-xson"/></xsl:template ><xsl:template match="*" mode="raw-to-xson"><xsl:apply-templates mode="raw-to-xson"/></xsl:template ><xsl:template match="o|l" mode="raw-to-xson"><xsl:apply-templates mode="raw-to-xson"/></xsl:template ><xsl:template match="l/v" mode="raw-to-xson"><xsl:element name="xson:item"><xsl:apply-templates mode="raw-to-xson"/></xsl:element ></xsl:template ><xsl:template match="a" mode="raw-to-xson"><xsl:variable name="name"><xsl:choose><xsl:when test="number(translate(n,\'&quot;\',\'\'))=translate(n,\'&quot;\',\'\')"><xsl:value-of select="concat(\'@\',translate(n,\'&quot;\',\'\'))"/></xsl:when ><xsl:otherwise><xsl:value-of select="translate(translate(n,\'&quot;\',\'\'),$invalidChars,\'@@@@@\')"/></xsl:otherwise ></xsl:choose ></xsl:variable ><xsl:element name="{translate($name,\'@\',\'_\')}"><xsl:if test="contains($name,\'@\')"><xsl:attribute name="xson:originalName"><xsl:value-of select="translate(n,\'&quot;\',\'\')"/></xsl:attribute ></xsl:if><xsl:if test="l"><xsl:attribute name="xi:type">xson:array</xsl:attribute ></xsl:if><xsl:apply-templates select="*" mode="raw-to-xson" /></xsl:element ></xsl:template ><xsl:template match="text()" mode="raw-to-xson"><xsl:value-of select="."/></xsl:template ><xsl:template match="text()[starts-with(.,\'&quot;\')]" mode="raw-to-xson"><xsl:value-of select="substring(.,2,string-length(.)-2)"/></xsl:template ><xsl:template match="text()[.=\'null\']|*[.=\'\']" mode="raw-to-xson" /><xsl:template match="text()[.=\'null\']" mode="raw-to-xson"><xsl:attribute name="xi:nil">true</xsl:attribute ></xsl:template ><xsl:template match="n" mode="raw-to-xson"></xsl:template ><xsl:template match="a[v=\'true\' or v=\'false\']/n" mode="raw-to-xson"><xsl:attribute name="xi:type">boolean</xsl:attribute ></xsl:template ><xsl:template match="e" mode="raw-to-xson"><xsl:value-of select="@v"/></xsl:template ><xsl:template match="a[number(v)=v]/n" mode="raw-to-xson"><xsl:attribute name="xi:type">numeric</xsl:attribute ></xsl:template ><xsl:template match="a[starts-with(v,\'&quot;\')]/n" mode="raw-to-xson"><xsl:attribute name="xi:type">string</xsl:attribute ></xsl:template ><xsl:template match="a[l]/n" mode="raw-to-xson"><xsl:attribute name="xi:type">xson:array</xsl:attribute ></xsl:template ><xsl:template match="a[o]/n" mode="raw-to-xson"><xsl:attribute name="xi:type">xson:object</xsl:attribute ></xsl:template ><xsl:template match="o[not(preceding-sibling::n)]" mode="raw-to-xson"><xsl:element name="xson:object"><xsl:apply-templates mode="raw-to-xson"/></xsl:element ></xsl:template ><xsl:template match="l[not(preceding-sibling::n)]" mode="raw-to-xson"><xsl:element name="xson:array"><xsl:apply-templates mode="raw-to-xson"/></xsl:element ></xsl:template ></xsl:stylesheet >'));

    return xson;
}

xdom.json.merge = function () {
    var response = (arguments[0] || {})
    for (let a = 1; a < arguments.length; a++) {
        var object = arguments[a]
        if (object && object.constructor == {}.constructor) {
            for (let key in object) {
                if (object[key] && object[key].constructor == {}.constructor) {
                    response[key] = xdom.json.merge(response[key], object[key]);
                } else {
                    response[key] = object[key];
                }
            }
        }
    }
    return response;
}

xdom.json.difference = function () {
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

xdom.json.toArray = function (json) {
    var array = []
    for (let key in json) {
        array.push(json[key]);
    }
    return array;
}

xdom.json.join = function (json, settings) {
    if (!(json && json.constructor == {}.constructor)) {
        return json;
    }
    var result = []
    var settings = (settings || {});
    var equal_sign = (settings["equal_sign"] || '=');
    var separator = (settings["separator"] || ' ');
    var for_each = (settings["for_each"] || function (element, index, array) {
        var quote = (settings["quote"] !== undefined ? settings["quote"] : '"');
        var regex = new RegExp(quote, "ig");
        if (element.value && quote) {
            element.value = quote + String(element.value).replace(regex, "\\$&") + quote;
        }
        array[index] = element.key + equal_sign + element.value;
    })
    for (let key in json) {
        result.push({ "key": key, "value": json[key] });
        //result.push({ "key": key, "value": (json[key] || "DEFAULT") });
    }
    result.forEach(for_each)
    var filter_function = (settings["filter_function"] || function (value, index, arr) {
        return value !== undefined;
    })
    return result.filter(filter_function).join(separator);
}

xdom.json.toAttributes = function (json) {
    json = Object.entries(json).reduce((filtered, [key, value]) => { if (value !== undefined) { filtered[key] = value; } return filtered; }, {})
    let attribs = new URLSearchParams(json);
    return [...attribs.entries()].reduce((params, entry) => { params.push(`${entry[0]}=${JSON.stringify(entry[1])}`); return params }, []).join(" ")
}

xdom.json.fromAttributes = function (attributes) {
    return JSON.parse('{' + (attributes.match(/(\w+)=(["'])([^\2]+?)\2/ig) || []).join(", ").replace(/(\w+)=(["'])([^\2]+?)\2/ig, '"$1":$2$3$2') + '}')
}

//xdom.json.fromAttributes = function (attributes) { //Version with createNode, witch is slower.
//    let json = {}
//    let node = xdom.xml.createNode(`<node ${attributes} />`);
//    [...node.attributes].map(attr => json[attr.nodeName] = attr.nodeValue);
//    return json
//}

xdom.xml.getXpath = function (node) {
    var xpath = '';
    xpath = (node.firstElementChild || node).nodeName;
    if (node.parentElement) {
        xpath = xdom.xml.getXpath(node.parentElement) + '/' + xpath;
    }
    return xpath;
}

xdom.data.search = function (xpath, dataset) {
    var ref;
    var dataset = (dataset || xdom.stores.active || xdom.Store().document)
    if (typeof (xpath) == "string") {
        ref = dataset.selectSingleNode(xpath)
    }
    return ref;
}

xdom.data.find = function (ref, dataset) {
    var dataset = (dataset || xdom.stores.active || xdom.Store())
    if (typeof (ref) == "string") {
        ref = dataset.selectSingleNode('//*[@x:id="' + ref + '" ]')
    }
    if (!ref) return;
    var exists = false;
    var return_value;
    if (dataset.contains(ref) || ref.nodeType == 2 && dataset.contains(ref.selectSingleNode('..'))) {
        return ref;
    }
    if (ref.nodeType == 2) {
        return dataset.selectSingleNode('//*[@x:id="' + (ref.ownerElement || document.createElement('p')).getAttribute("x:id") + '"]/@' + ref.name);
    } else {
        return (dataset.selectSingleNode('//*[@x:id="' + (ref.documentElement || ref || document.createElement('p')).getAttribute("x:id") + '"]') || xdom.stores.active.selectSingleNode(xdom.xml.getXpath(ref)));
    }
}

xdom.data.deepFind = function (ref) {
    var target = xdom.stores.active.find(ref);
    if (target) {
        return target;
    }
    //xdom.stores.filter((nombre, document) => document.selectSingleNode(`//*[@x:id="${typeof (ref) == 'string' ? ref : ref.getAttribute("x:id")}"]`))
    for (let xDocument in xdom.stores) {
        target = xdom.stores[xDocument].find(ref);
        if (target) {
            return target;
        }
    }
    return target;
}

xdom.dom.allowDrop = function (ev) {
    ev.preventDefault();
}

xdom.dom.drag = function (ev) {
    ev.dataTransfer.setData("text", ev.target.id);
}

xdom.dom.drop = function (ev) {
    ev.preventDefault();
    var data = ev.dataTransfer.getData("text");
    ev.target.appendChild(document.getElementById(data));
}

xdom.storage.clearCache = function (document_name) {
    if (typeof (Storage) !== "undefined") {
        localStorage.clear();
    } else {
        console.error('Storage is not supported by your browser');
    }
}

xdom.storage.setKey = function (key, value) {
    if (typeof (Storage) !== "undefined") {
        let session_id = (xdom.session.id && `${xdom.session.id}/` || `${location.hostname}${location.pathname.replace(/[^/]+$/, "")}`);

        key = `${session_id}${key}`;
        if (value === undefined) {
            localStorage.removeItem(key);
        } else if ((value instanceof Node || value instanceof xdom.Store) && value.toString) {
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

xdom.storage.getKey = function (key) {
    //if (!eval(xdom.storage.enabled) && key != 'xdom.storage.enabled') return;
    if (typeof (Storage) !== "undefined") {
        let session_id = (xdom.session.id && `${xdom.session.id}/` || `${location.hostname}${location.pathname.replace(/[^/]+$/, "")}`);
        var document = JSON.parse(localStorage.getItem(`${session_id}${key}`));
        if (document) {
            return document;
        }
    } else {
        console.error('Storage is not supported by your browser')
    }
}

xdom.storage.syncSession = function (event) {
    if (!event) { event = window.event; }
    if (!event.newValue) return;
    let session_id = (xdom.session.id && `${xdom.session.id}/` || `${location.hostname}${location.pathname.replace(/[^/]+$/, "")}`);
    if (event.key.match(new RegExp(`^${session_id}`, 'i'))) {
        xdom.session[event.key.replace(new RegExp(`^${session_id}`, 'i'), '')] = event.newValue;
    }
};

if (window.addEventListener) {
    window.addEventListener("storage", xdom.storage.syncSession, false);
} else {
    window.attachEvent("onstorage", xdom.storage.syncSession);
};

xdom.data.removeMessage = function (target) {
    message = target instanceof Element && target || xdom.stores.active.selectSingleNode(`//x:message[@x:id="${target}"]`);
    if (message) {
        message.remove();
        if (message.ownerDocument.documentElement) {
            xdom.stores.active.render(/*true*/);
        } else {
            navigate_back = true;
        }
    }
}

xdom.listener.keypress = function (e = {}) {
    xdom.listener.keypress.ctrlKey = e.ctrlKey;
    xdom.listener.keypress.shiftKey = e.shiftKey;
    xdom.listener.keypress.altKey = e.altKey;
    xdom.listener.keypress.tabKey = (e.keyCode == 9);
    xdom.dom.triggeredByTab = (xdom.dom.triggeredByTab || xdom.listener.keypress.tabKey);
    xdom.listener.keypress.escKey = (e.keyCode == 27);
    if (xdom.debug["xdom.listener.keypress"]) {
        console.log(String.fromCharCode(e.keyCode) + " --> " + e.keyCode)
    }
}

xdom.listener.keypress.last_key = undefined;
xdom.listener.keypress.streak_count = 0;

document.onkeydown = function (event) {
    if (![9].includes(event.keyCode)) {
        xdom.delay(1).then(() => {
            xdom.state.save(event.srcElement);
        })
    }
    if (event.keyCode == xdom.listener.keypress.last_key) {
        ++xdom.listener.keypress.streak_count;
    } else {
        xdom.listener.keypress.last_key = event.keyCode;
        xdom.listener.keypress.streak_count = 1;
    }
    if (xdom.debug["xdom.listener.keypress.keydown"]) {
        if (!xdom.debug["xdom.listener.keypress"]) {
            console.log("key pressed: " + event.keyCode)
        }
        console.log("xdom.listener.keypress.streak_count: " + xdom.listener.keypress.streak_count)
    }
    if (event.keyCode == 27) {
        xdom.data.removeMessage();
        return;
    }
    xdom.listener.keypress(event);
    if (xdom.listener.keypress.altKey || xdom.listener.keypress.shiftKey || xdom.listener.keypress.ctrlKey) {
        if (this.keyInterval != undefined) {
            window.clearTimeout(this.keyInterval);
            this.keyInterval = undefined;
        }
        this.keyInterval = window.setTimeout(function () {
            xdom.listener.keypress();
            this.keyInterval = undefined;
        }, 1000);
        return;
    } //if combined with alt/shift/ctrl keys 
    // in grids, this function will allow move up and down between elements
    var srcElement = event.srcElement;
    if (event.keyCode == 40) {
        if (srcElement.nodeName.toLowerCase() == 'select' && (srcElement.size || xdom.browser.isIE() || xdom.browser.isEdge())) return;
        currentNode = srcElement.source;
        if (!currentNode) return false;
        nextNode = currentNode.selectSingleNode('../following-sibling::*[not(@x:deleting="true")][1]/*[local-name()="' + currentNode.nodeName + '"]')
        if (nextNode) {
            document.getElementById(nextNode.getAttribute('x:id')).focus();
        }
        event.preventDefault();
    } else if (event.keyCode == 38) {
        if (srcElement.nodeName.toLowerCase() == 'select' && (srcElement.size || xdom.browser.isIE() || xdom.browser.isEdge())) return;
        currentNode = srcElement.source;
        if (!currentNode) return false;
        nextNode = currentNode.selectSingleNode('../preceding-sibling::*[not(@x:deleting="true")][1]/*[local-name()="' + currentNode.nodeName + '"]')
        if (nextNode) {
            document.getElementById(nextNode.getAttribute('x:id')).focus();
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
    //    xdom.dom.activeElementCaretPosition = parseFloat(String(xdom.dom.getCaretPosition(document.activeElement)).split(",").pop()) + 1;
    //}
};

document.onkeyup = function (e) {
    xdom.listener.keypress.last_key = e.keyCode;
    xdom.listener.keypress(e);
    window.setTimeout(function () { xdom.listener.keypress(e); }, 300);
};

// TODO: Modificar listeners para que funcion con el método de XOVER
xdom.dom.beforeunload = async function (e) {
    //xdom.state.save();
    let stores = await xdom.database.stores;
    for (let hashtag in xdom.stores) {
        console.log("Saving " + hashtag)
        stores.put((xdom.stores[hashtag].initiator || xdom.stores[hashtag]), hashtag)
        //xdom.session.setKey(hashtag, (xdom.stores[hashtag].initiator || xdom.stores[hashtag]));
    }
    history.replaceState(history.state || {}, {}, (window.top || window).location.hash || '/');
    console.log("checking if we should display confirmation dialog");
    var shouldCancel = false;
    if (shouldCancel) {
        console.log("displaying confirmation dialog");
        e.preventDefault();
        e.returnValue = false;
    }
}
var eventName = xdom.browser.isIOS() ? "pagehide" : "beforeunload";

window.addEventListener(eventName, xdom.dom.beforeunload);

xdom.dom.print = function () {
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

xdom.listener.on('stateChanged::loading', function ({ target: store, new: value }) {
    if (event.defaultPrevented) return;
    if (store instanceof xdom.Store && store.isActive) {
        if (value) {
            //targetDocument = ((document.activeElement || {}).contentDocument || document);
            //xdom.library["loading.xslt"].render({ target: , action: "append" });
            let last_stylesheet = store.stylesheets.pop();
            let document = store.document;
            document.render(document.createProcessingInstruction('xml-stylesheet', { type: 'text/xsl', href: "loading.xslt", target: last_stylesheet && last_stylesheet.target || 'body', action: "append" }));
        } else {
            [...document.querySelectorAll(`[xo-store='${store.tag}'][xo-stylesheet='loading.xslt']`)].removeAll();
        }
    }
});

xdom.listener.on("focusout", function (event) {
    if (event.defaultPrevented) return;
    xdom.dom.lastBluredElement = event.target;

    if (((arguments || {}).callee || {}).caller === xdom.dom.clear) {
        xdom.dom.activeElement = event.target;
    } else {
        xdom.dom.bluredElement = event.target;
        if (xdom.debug["focusout"]) {
            console.log(event.target);
        }
    }
})

xdom.listener.on('click', function (event) {
    if (event.defaultPrevented) return;
    var srcElement = xdom.dom.findClosestElementWithAttribute(event.target, "href");
    var hashtag = (srcElement ? srcElement.getAttribute("href") : "");

    if (!hashtag.match(/^#/)) {
        return;
    }
    if (hashtag !== undefined && hashtag != (window.top || window).location.hash) {
        custom_event = new xdom.listener.Event('beforeHashChange', [hashtag, (window.top || window).location.hash])
        window.top.dispatchEvent(custom_event);
    }
    return event.preventDefault();
});

xdom.listener.on(["change", "click"], function (event) {
    if (event.defaultPrevented) return;
    xdom.dom.bluredElement = event.target;
    xdom.delay(40).then(() => {
        xdom.dom.triggeredByTab = xdom.listener.keypress.tabKey;
    })
})

xdom.listener.on("click", function (event) {
    if (event.defaultPrevented) return;
    xdom.delay(40).then(() => {
        let target_store = event.target.store;
        if (target_store) {
            if (target_store.library.reload.interval.continue) {
                target_store.library.reload.interval.continue();
            }
            if (xdom.listener.keypress.ctrlKey && !xdom.listener.keypress.shiftKey && !xdom.listener.keypress.altKey/* && target_tag !== (window.top || window).location.hash)*/) {
                let target_tag = target_store.tag;
                //target_store.detectActive();
                xdom.state.update({ active: target_tag, hash: target_tag });
            }
        }
    })
})

xdom.listener.on("contextmenu", function (event) {
    if (event.defaultPrevented) return;
    xdom.delay(40).then(() => {
        let target_store = event.target.store;
        if (target_store) {
            if (target_store.library.reload.interval.pause) {
                target_store.library.reload.interval.pause();
            }
        }
    })
})

var _Network_state = true;
xdom.browser.updateIndicator = function () {
    if (navigator.onLine) {
        console.info("online")
        _Network_state = true;
    } else {
        console.warn("offline")
        _Network_state = false;
    }
}
xdom.listener.on(["online", "offline"], xdom.browser.updateIndicator);
xdom.browser.updateIndicator();

xdom.string = {}
xdom.string.htmlDecode = function (string) {
    var txt = document.createElement("textarea");
    txt.innerHTML = string;
    return txt.value;
}

xdom.string.getFileParts = function (file_name = '') {
    let parts = {}
    parts["extension"] = file_name.lastIndexOf('.') != -1 && file_name.substring(file_name.lastIndexOf('.') + 1) || undefined;
    parts["name"] = file_name.substring(file_name.lastIndexOf('/') + 1)
    parts["path"] = file_name.substring(0, file_name.lastIndexOf('/') + 1)
    return parts;
}

xdom.json.isValid = function (input) {
    try {
        return [{}.constructor].includes(JSON.parse(JSON.stringify(input)).constructor)
    } catch (e) {
        return false;
    }
    return true;
}

xdom.json.tryParse = function (input) {
    let output;
    if (xdom.json.isValid(input)) {
        return input;
    }
    try {
        output = eval(`(${input})`);
    } catch (e) {
        output = eval(`(${JSON.stringify(input)})`)
    }
    return output;
}

Object.defineProperty(xdom.string, 'replace', {
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

xdom.string.trim = function (text) {
    if (typeof (text) != "string") return text;
    return text.replace(/\s+$/, '').replace(/^\s+/, '')
}

xdom.string.toTitleCase = function (str) {
    /*Code obtained from https://stackoverflow.com/questions/196972/convert-string-to-title-case-with-javascript */
    var i, j, lowers, uppers;
    if (!str) return str;
    if (xdom.string.isEmail(str)) {
        return str.toLowerCase();
    } else if (xdom.string.isRFC(str) || xdom.string.isCURP(str)) {
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

xdom.string.isRFC = function (str) {
    if (/^([A-Z,Ñ,&]{3,4}([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|1[0-9]|2[0-9]|3[0-1])[A-Z|\d]{3})$/.test(str)) {
        return (true)
    }
    return (false)
}

xdom.string.isEmail = function (str) {
    if (/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(str)) {
        return (true)
    }
    return (false)
}

xdom.string.isCURP = function (str) {
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

function isObject(a) {
    return (a && typeof a == 'object') || isFunction(a);
}

function isEmpty(str) {
    return (!str || /^\s*$/.test(str));
}

xdom.dom.getCaretPosition = function (elem) {
    let caret_pos, caret_start, caret_end;

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

xdom.dom.setCaretPosition = function (elem, caret_pos) {
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
                    xdom.state.activeCaret = [start, end];
                } else {
                    range.move('character', start);
                    range.select();
                    xdom.state.activeCaret = [start];
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
                    xdom.state.activeCaret = [start, end];
                } else {
                    elem.setSelectionRange(start, start);
                    xdom.state.activeCaret = [start];
                }
            } else {
                elem.focus();
            }
        }
    }
}

xdom.dom.elementVisible = function (el, container) {
    if (container.scrollTop > el.offsetTop || container.scrollLeft > el.offsetLeft) {
        return false;
    }
    return true;
}

xdom.data.getScrollPosition = function (target) {
    var coordinates = ((target || xdom.stores.active.documentElement || document.createElement('p')).selectNodes('@state:x-position|@state:y-position') || []).reduce((json, attr) => { json[attr.localName.replace('-position', '')] = attr.value; return json; }, {});
    return coordinates;
}

xdom.dom.getScrollPosition = function (el) {
    var targetDocument = ((document.activeElement || {}).contentDocument || document);
    var el = (el || targetDocument.activeElement || targetDocument.querySelector('body'));//(el || window);
    scrollParent = (xdom.dom.getScrollParent(el) || targetDocument.querySelector('body'));
    var coordinates =
    {
        x: (scrollParent.pageXOffset !== undefined ? scrollParent.pageXOffset : scrollParent.scrollLeft),
        y: (scrollParent.pageYOffset !== undefined ? scrollParent.pageYOffset : scrollParent.scrollTop),
        target: scrollParent
    }
    return coordinates;
}


xdom.dom.setScrollPosition = function (el, coordinates) {
    el = (typeof (el) == 'string' && document.querySelector(el) || el);
    if (el) {
        if (!(coordinates && el.scrollTo)) {
            return;
        }
        el.scrollTo(coordinates.x, coordinates.y);
    } else {
        Object.entries(xdom.state.scrollableElements).map(([selector, coordinates]) => {
            xdom.dom.setScrollPosition(selector, coordinates)
        })
    }
}

xdom.dom.getScrollParent = function (el) {
    if (el == null) {
        return null;
    }
    if (el.scrollHeight > el.clientHeight && (el.scrollTop || el.scrollLeft)) {
        return el;
    } else {
        return xdom.dom.getScrollParent(el.parentNode);
    }
}

xdom.dom.scrollableElements = (history.state || {}).scrollableElements || {};
xdom.dom.getScrollableElements = function (el) {
    var target = (el || (document.activeElement || {}).contentDocument || document);
    xdom.stores.active.selectNodes("//*[@state:x-position]").filter(node => {
        (node.getAttribute("state:x-position") > 0 || node.getAttribute("state:y-position") > 0)/* && document.querySelector(`#${node.getAttribute("x:id")}`)*/
    });
    return [...(el && [el] || []), ...target.querySelectorAll("*")].filter(el => el.scrollHeight > el.clientHeight && (el.scrollTop || el.scrollLeft));
}

xdom.dom.updateScrollableElements = function (el) {
    var target = (el || (document.activeElement || {}).contentDocument || document);
    let scrollable = xdom.dom.getScrollableElements(target);
    scrollable.map(el => {
        let coordinates = xdom.dom.getScrollPosition(el);
        //if (el.source) {
        //    el.source.setAttributeNS(null, `state:x-position`, coordinates.x);
        //    el.source.setAttributeNS(null, `state:y-position`, coordinates.y);
        //}

        path = el.selector;
        xdom.dom.scrollableElements[path] = {}
        xdom.dom.scrollableElements[path]["x"] = coordinates.x;
        xdom.dom.scrollableElements[path]["y"] = coordinates.y;
    });
    xdom.state.scrollableElements = xdom.dom.scrollableElements;
    //xdom.stores.active.selectNodes("//*[@state:x-position]").filter(node => {
    //    return (node.getAttribute("state:x-position") > 0 || node.getAttribute("state:y-position") > 0)/* && document.querySelector(`#${node.getAttribute("x:id")}`)*/
    //}).map(node => {
    //    xdom.dom.scrollableElements[node.getAttribute("x:id")] = {}
    //    xdom.dom.scrollableElements[node.getAttribute("x:id")]["x"] = node.getAttribute("state:x-position");
    //    xdom.dom.scrollableElements[node.getAttribute("x:id")]["y"] = node.getAttribute("state:y-position");
    //});
}

xdom.dom.getNextElement = function (src) {
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

xdom.dom.getPrecedingElement = function (src) {
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

xdom.dom.focusNextElement = function () {
    var nextElement = xdom.dom.getNextElement();
    nextElement.focus();
}

xdom.debug.brokenXmlAttributes = function (node) {
    return node.selectNodes(`@*`).filter(attr => (!attr.prefix && attr.name.indexOf(':') != -1))
}

xdom.modernize = function (targetWindow) {
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
            Object.defineProperty(base.prototype, "constructor", descriptor);
            return proxy;
        }

        Date.prototype.addDays = function (days = 0) {
            var date = new Date(this.valueOf());
            date.setDate(date.getDate() + days);
            return date;
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

        if (!Object.prototype.hasOwnProperty('cloneObject')) {
            Object.defineProperty(Object.prototype, 'cloneObject', {
                value: function () {
                    return xdom.json.merge({}, this);//JSON.parse(JSON.stringify(this));
                },
                writable: false, enumerable: false, configurable: false
            });
        }

        if (!Object.prototype.hasOwnProperty('filter')) {
            Object.defineProperty(Object.prototype, 'filter', {
                get: function () {
                    return function (_filter_function) {
                        var subset = {}
                        Object.entries(this).forEach(([key, value]) => {
                            if (_filter_function && _filter_function.apply && _filter_function.apply(this, [key, value])) {
                                subset[key] = value;
                            }
                        })
                        return subset;
                    }
                }, set: function (input) {
                    return;
                }, enumerable: false, configurable: false
            });
        }

        if (!Object.prototype.hasOwnProperty('merge')) {
            Object.defineProperty(Object.prototype, 'merge', {
                value: function () {
                    let self = this;
                    for (let a = 0; a < arguments.length; a++) {
                        var object = arguments[a]
                        if (object && object.constructor == {}.constructor) {
                            for (let key in object) {
                                if (object[key] && object[key].constructor == {}.constructor) {
                                    self[key] = Object.prototype.merge.call(self[key] || {}, object[key]);
                                } else {
                                    let new_value = object[key];
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
            Node.prototype.selectSingleNode = function (cXPathString, xNode) {
                if (!xNode) { xNode = this; }
                if (xNode instanceof xdom.Store) {
                    xNode = (xNode.document || xNode);
                }
                if (!cXPathString) {
                    return null;
                }
                let namespace = this.resolveNS("");
                if (!cXPathString.match(/[^\w\d\-\_]/g) && namespace) {
                    cXPathString = `*[namespace-uri()='${namespace}' and name()='${cXPathString}']`
                }
                let xItems = this.selectNodes(`(${cXPathString})[1]`, xNode);
                if (xItems.length > 0) { return xItems[0]; }
                else { return null; }
            }
            //XMLDocument.prototype.selectFirst = XMLDocument.prototype.selectSingleNode

            Node.prototype.selectNodes = function (cXPathString, xNode) {
                if (!xNode) { xNode = this; }
                //if (xNode instanceof xdom.Store) {
                xNode = (xNode.document || xNode);
                //}
                if (!cXPathString.match(/[^\w\d\-\_]/g)) {
                    cXPathString = `*[namespace-uri()='${this.resolveNS("")}' and name()='${cXPathString}']`
                }
                let contextNode = xNode.documentElement || xNode;
                let nsResolver = (function (element) {
                    let resolver = element instanceof Document ? element.createNSResolver(element) : element.ownerDocument.createNSResolver(element);

                    return function (prefix) {
                        return resolver.lookupNamespaceURI(prefix) || resolver.lookupNamespaceURI(prefix == '_' && '') || xdom.xml.namespaces[prefix];
                    };
                }(contextNode))

                let selection = new Array;
                try {
                    let aItems = (xNode.ownerDocument || xNode).evaluate(cXPathString, xNode, nsResolver, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null)
                    for (let i = 0; i < aItems.snapshotLength; i++) {
                        selection[i] = aItems.snapshotItem(i);
                        if (selection[i] instanceof ProcessingInstruction) {
                            selection[i] = new xdom.ProcessingInstruction(selection[i]);
                        }
                    }
                } catch (e) {
                    if (e.message.match(/contains unresolvable namespaces/g) && ((arguments || {}).callee || {}).caller !== XMLDocument.prototype.selectNodes && XMLDocument.prototype.selectNodes.caller !== Element.prototype.selectNodes) {
                        let prefixes = cXPathString.match(/\w+(?=\:)/g);
                        prefixes = [...new Set(prefixes)]; //remueve duplicados
                        let target = xNode;
                        let all_namespaces = xdom.xml.normalizeNamespaces(target).getNamespaces();
                        let new_namespaces = prefixes.filter(prefix => (all_namespaces[prefix] || xdom.xml.namespaces[prefix]))

                        if (new_namespaces.length) {
                            new_namespaces.map(prefix => {
                                (target.documentElement || target).setAttributeNS('http://www.w3.org/2000/xmlns/', `xmlns:${prefix}`, (all_namespaces[prefix] || xdom.xml.namespaces[prefix]));
                            });
                            xNode.selectNodes(cXPathString);
                        } else {
                            throw (e);
                        }
                    } else {
                        throw (e);
                    }
                }
                return new xdom.NodeSet(selection);
            }
            //XMLDocument.prototype.selectAll = XMLDocument.prototype.selectNodes

            if (!Node.prototype.hasOwnProperty('resolveNS')) {
                Object.defineProperty(Node.prototype, "resolveNS", {
                    get: function () {
                        let element = this;
                        let resolver = element instanceof Document ? element.createNSResolver(element) : element.ownerDocument.createNSResolver(element);

                        return function (prefix) {
                            return resolver.lookupNamespaceURI(prefix) || resolver.lookupNamespaceURI(prefix == '_' && '');
                        };
                    }
                });
            }

            XMLDocument.prototype.compareTo = function (document, stop_at_first_change) {
                let xsl_compare = this.transform(xdom.xml.createDocument(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:c="http://panax.io/xml/compare" version="1.0" id="panax_xml_compare_xsl"><xsl:output method="xml"></xsl:output><xsl:strip-space elements="*"></xsl:strip-space><xsl:variable name="smallcase" select="'abcdefghijklmnopqrstuvwxyz'"></xsl:variable><xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'"></xsl:variable><xsl:template match="/"><xsl:element name="xsl:stylesheet"><xsl:copy-of select="//namespace::*"/><xsl:attribute name="version">1.0</xsl:attribute><xsl:element name="xsl:template"><xsl:attribute name="match">/</xsl:attribute><xsl:element name="results"><xsl:element name="xsl:apply-templates"></xsl:element></xsl:element></xsl:element><xsl:element name="xsl:template"><xsl:attribute name="match">*</xsl:attribute><xsl:element name="change" namespace="http://panax.io/xml/compare"><xsl:attribute name="c:position"><xsl:value-of select="'{count(preceding-sibling::*)+1}'"></xsl:value-of></xsl:attribute><xsl:attribute name="c:namespace"><xsl:value-of select="'{namespace-uri()}'"></xsl:value-of></xsl:attribute><xsl:attribute name="c:name"><xsl:value-of select="'{name()}'"></xsl:value-of></xsl:attribute><xsl:attribute name="c:type"><xsl:text>Node</xsl:text></xsl:attribute><xsl:element name="xsl:copy-of"><xsl:attribute name="select">@*</xsl:attribute></xsl:element><xsl:element name="xsl:apply-templates"></xsl:element></xsl:element></xsl:element><xsl:element name="xsl:template"><xsl:attribute name="match">text()</xsl:attribute><xsl:element name="change" namespace="http://panax.io/xml/compare"><xsl:attribute name="c:type"><xsl:text>Text</xsl:text></xsl:attribute><xsl:attribute name="c:position"><xsl:value-of select="'{count(preceding-sibling::*)}'"></xsl:value-of></xsl:attribute><xsl:attribute name="c:text"><xsl:value-of select="'{.}'"></xsl:value-of></xsl:attribute></xsl:element></xsl:element><xsl:apply-templates></xsl:apply-templates></xsl:element></xsl:template><xsl:template name="escape-xml"><xsl:param name="wrapper">&quot;</xsl:param><xsl:param name="text"></xsl:param><xsl:if test="$text != ''"><xsl:variable name="head" select="substring($text, 1, 1)"></xsl:variable><xsl:variable name="tail" select="substring($text, 2)"></xsl:variable><xsl:choose><xsl:when test="$head = '&amp;'">&amp;amp;</xsl:when><xsl:when test="$head = '&lt;'">&amp;lt;</xsl:when><xsl:when test="$head = '&gt;'">&amp;gt;</xsl:when><xsl:when test="$head = '&quot;'">&amp;quot;</xsl:when><xsl:when test="$wrapper=&quot;'&quot; and $head = &quot;'&quot;">&amp;apos;</xsl:when><xsl:otherwise><xsl:value-of select="$head"></xsl:value-of></xsl:otherwise></xsl:choose><xsl:call-template name="escape-xml"><xsl:with-param name="text" select="$tail"></xsl:with-param></xsl:call-template></xsl:if></xsl:template><xsl:template name="escape-quot"><xsl:param name="string"></xsl:param><xsl:variable name="quot">&quot;</xsl:variable><xsl:variable name="escaped-quot">&amp;quot;</xsl:variable><xsl:text>&quot;</xsl:text><xsl:choose><xsl:when test="contains($string, $quot)"><xsl:value-of select="substring-before($string, $quot)"></xsl:value-of><xsl:text>&quot;,'&quot;',</xsl:text><xsl:call-template name="escape-quot"><xsl:with-param name="string" select="substring-after($string, $quot)"></xsl:with-param></xsl:call-template><xsl:text>,&quot;</xsl:text></xsl:when><xsl:otherwise><xsl:value-of select="$string"></xsl:value-of></xsl:otherwise></xsl:choose><xsl:text>&quot;</xsl:text></xsl:template><xsl:template name="escape-apos"><xsl:param name="string"></xsl:param><xsl:choose><xsl:when test="contains($string, &quot;'&quot;)"><xsl:value-of select="substring-before($string, &quot;'&quot;)"></xsl:value-of><xsl:text>'</xsl:text><xsl:call-template name="escape-apos"><xsl:with-param name="string" select="substring-after($string, &quot;'&quot;)"></xsl:with-param></xsl:call-template></xsl:when><xsl:otherwise><xsl:value-of select="$string"></xsl:value-of></xsl:otherwise></xsl:choose></xsl:template><xsl:template match="*|text()"><xsl:apply-templates></xsl:apply-templates><xsl:element name="xsl:template"><xsl:attribute name="match"><xsl:apply-templates select="." mode="path"></xsl:apply-templates></xsl:attribute><xsl:element name="ok" namespace="http://panax.io/xml/compare"><xsl:attribute name="c:position"><xsl:value-of select="'{count(preceding-sibling::*)+1}'"></xsl:value-of></xsl:attribute><xsl:attribute name="c:name"><xsl:value-of select="'{name()}'"></xsl:value-of></xsl:attribute><xsl:copy-of select="@*"></xsl:copy-of><xsl:element name="xsl:apply-templates"></xsl:element></xsl:element></xsl:element></xsl:template><xsl:template match="*" mode="simple-path"><xsl:param name="position"><xsl:value-of select="count(preceding-sibling::*)+1"></xsl:value-of></xsl:param><xsl:apply-templates select="ancestor::*[1]" mode="simple-path"></xsl:apply-templates><xsl:text>/*</xsl:text><xsl:text>[</xsl:text><xsl:value-of select="$position"></xsl:value-of><xsl:text>]</xsl:text></xsl:template><xsl:template match="*" mode="path"><xsl:param name="position"><xsl:value-of select="count(preceding-sibling::*)+1"></xsl:value-of></xsl:param><xsl:apply-templates select="ancestor::*[1]" mode="simple-path"></xsl:apply-templates><xsl:text>/*</xsl:text><xsl:text>[</xsl:text><xsl:value-of select="$position"></xsl:value-of><xsl:text>]</xsl:text><xsl:text>[local-name()='</xsl:text><xsl:value-of select="local-name()"></xsl:value-of><xsl:text>']</xsl:text><xsl:text>[namespace-uri()='</xsl:text><xsl:value-of select="namespace-uri()"></xsl:value-of><xsl:text>']</xsl:text><xsl:text>[1=1 </xsl:text><xsl:for-each select="@*"><xsl:variable name="value"><xsl:text>concat('',</xsl:text><xsl:call-template name="escape-quot"><xsl:with-param name="string"><xsl:value-of select="." disable-output-escaping="yes"></xsl:value-of></xsl:with-param></xsl:call-template><xsl:text>)</xsl:text></xsl:variable><xsl:value-of select="concat(' and @',name(.),'=',$value)"></xsl:value-of></xsl:for-each><xsl:text>]</xsl:text></xsl:template><xsl:template match="text()" mode="path"><xsl:param name="position"><xsl:value-of select="count(preceding-sibling::*)+1"></xsl:value-of></xsl:param><xsl:apply-templates select="ancestor::*[1]" mode="simple-path"></xsl:apply-templates><xsl:text>/text()</xsl:text><xsl:text>[</xsl:text><xsl:value-of select="$position"></xsl:value-of><xsl:text>]</xsl:text><xsl:variable name="unescaped-value"><xsl:value-of select="." disable-output-escaping="yes"></xsl:value-of></xsl:variable><xsl:variable name="value"><xsl:text>concat('',</xsl:text><xsl:call-template name="escape-quot"><xsl:with-param name="string"><xsl:value-of select="." disable-output-escaping="yes"></xsl:value-of></xsl:with-param></xsl:call-template><xsl:text>)</xsl:text></xsl:variable><xsl:value-of select="concat(&quot;[.=&quot;,$value,&quot;]&quot;)"></xsl:value-of></xsl:template></xsl:stylesheet>`));
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
                        [...document.querySelectorAll(`#${node.getAttribute("x:id")},[xo-store='${node.getAttribute("x:id")}']`)].map(target => target.style.outline = '#f00 solid 2px');
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
                        let buildQuerySelector = function (target, path = []) {
                            if (!(target && target.parentNode)) {
                                return path.join(" > ");
                            } else if (target.id) {
                                path.unshift(`${target.tagName}#${target.id}`);
                            } else if ((target.classList || []).length) {
                                let classes = [...target.classList].filter(class_name => !class_name.match("[.]"));
                                path.unshift(target.tagName + (classes.length && '.' + classes.join(".") || ""));
                            } else if (target.nodeName == '#text') {
                                path.unshift(buildQuerySelector(target.parentNode, path.flat()));
                            } else {
                                path.unshift(target.tagName || '*');
                            }

                            if (target.ownerDocument.querySelector(path.join(" > ")) === target) {
                                return path.join(" > ");
                            } else if (target.parentNode && target.parentNode.querySelector(path.join(" > "))) {
                                let position = target.parentNode && [...target.parentNode.children].findIndex(el => el == target);
                                if (position) {
                                    path[path.length - 1] = `${path[path.length - 1]}:nth-child(${position + 1})`;
                                }
                                path.unshift(buildQuerySelector(target.parentNode, []));
                            } else {
                                return path.join(" > ");
                            }
                            return path.flat().join(" > ");
                        }

                        return buildQuerySelector(this);
                    }

                });
            }

            var original_createProcessingInstruction = XMLDocument.prototype.createProcessingInstruction;
            XMLDocument.prototype.createProcessingInstruction = function (target, data) {
                if (target) {
                    let last_stylesheet = this.selectNodes("processing-instruction('xml-stylesheet')").pop();
                    let definition = data.constructor === {}.constructor && xdom.json.toAttributes(data) || data instanceof ProcessingInstruction && data.textContent || data
                    let piNode = new xdom.ProcessingInstruction(original_createProcessingInstruction.call(this, 'xml-stylesheet', definition));
                    return piNode;
                }
            }

            XMLDocument.prototype.toClipboard = function () {
                let source = this;
                var dummyContent = source.toString();
                var dummy = (document.createElement('input'));
                dummy.value = dummyContent;
                document.body.appendChild(dummy);
                dummy.select();
                document.execCommand('copy');
                dummy.remove();
                return;
            }

            if (!XMLDocument.prototype.hasOwnProperty('type')) {
                Object.defineProperty(XMLDocument.prototype, 'type', {
                    get: function () {
                        let self = this;
                        return (Object.entries(xdom.xml.namespaces).find(([key, namespace]) => self.documentElement && namespace == self.documentElement.namespaceURI) || [])[0] || (this.documentElement || {}).prefix || "xml";
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
                        let stylesheets_nodes = this.selectNodes("processing-instruction('xml-stylesheet')");
                        Object.defineProperty(stylesheets_nodes, 'getDocuments', {
                            value: function () {
                                let docs = []
                                for (let stylesheet of this) {
                                    docs.push(stylesheet.document)
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
                    if (this instanceof xdom.Store) {
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
                    //    let stylesheet = xdom.json.fromAttributes(stylesheets_nodes[s].textContent);
                    //    Object.defineProperty(stylesheet, 'ownerDocument', {
                    //        value: document
                    //    });
                    //    Object.defineProperty(stylesheet, 'document', {
                    //        get: function () {
                    //            return ((this.ownerDocument.store || {}).library || {})[this.href] || xdom.library[this.href]
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
                    //        //xdom.dom.refresh();
                    //    },
                    //    writable: false, enumerable: false, configurable: false
                    //});
                    Object.defineProperty(stylesheets_nodes, 'getDocuments', {
                        value: function () {
                            let docs = []
                            for (let stylesheet of this) {
                                docs.push(this.document);
                                //docs.push(this.ownerDocument.store.library[stylesheet.href] || xdom.library[stylesheet.href])
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

            XMLDocument.prototype.addStylesheet = function (definition, target) {
                let style_definition;
                let document = (this.document || this);
                if (definition.constructor === {}.constructor) {
                    definition = xdom.json.merge({ type: 'text/xsl' }, definition);
                    style_definition = xdom.json.toAttributes(definition);
                } else {
                    style_definition = definition
                }
                if (!this.getStylesheet(definition.href)) {
                    var pi = document.createProcessingInstruction('xml-stylesheet', style_definition);
                    if (this.store) {
                        this.store.render(/*true*/);
                    }
                    document.insertBefore(pi, target || document.selectSingleNode(`(processing-instruction('xml-stylesheet')${definition.role == 'init' ? '' : definition.role == 'binding' ? `[not(contains(.,'role="init"') or contains(.,'role="binding"'))]` : '[1=0]'} | *[1])[1]`));
                    return pi;
                }
            }

            var toString_original = Node.prototype.toString;
            Node.prototype.toString = function () {
                if (this instanceof HTMLElement) {
                    return toString_original
                } else {
                    return new XMLSerializer().serializeToString(this);
                }
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

            if (!Element.prototype.hasOwnProperty('source')) {
                Object.defineProperty(Element.prototype, 'source', { /*Estaba con HTMLElement, pero los SVG los ignoraba. Se deja abierto para cualquier elemento*/
                    get: function () {
                        let self = this;
                        let store = this.store;
                        if (!store) {
                            return null;
                        } else {
                            let node = store.find(this.getAttribute("xo-source")) || /*store.find(this.name) || */store.find(this.id) || store.find([this.closest("[xo-scope]")].map(el => el && el.getAttribute("xo-scope") || null)[0]);
                            //return attribute || node || store;
                            //if (!node) {
                            //    throw ("Node doesn't exist anymore!")
                            //}
                            if (node && this.getAttribute("xo-attribute")) {
                                if (node.getAttribute(this.getAttribute("xo-attribute")) === null) {
                                    node.setAttribute(this.getAttribute("xo-attribute"), "");
                                }
                                return node.selectSingleNode(`@${this.getAttribute("xo-attribute")}`);
                            }
                            return node;
                        }
                    }
                });
            }

            if (!Element.prototype.hasOwnProperty('store')) {
                Object.defineProperty(Element.prototype, 'store', {
                    get: function () {
                        if (this.ownerDocument instanceof XMLDocument) {
                            return this.ownerDocument.store
                        } else {
                            let node = this.parentElement && this || this.parentNode || this;
                            let store_name = [node.closest && node.closest("[xo-store]")].map(el => el && el.getAttribute("xo-store") || null)[0];
                            let store = store_name && store_name in xdom.stores && xdom.stores[store_name] || null;
                            return store;
                        }
                    }
                });
            }

            if (!Element.prototype.hasOwnProperty('stylesheet')) {
                Object.defineProperty(Element.prototype, 'stylesheet', {
                    get: function () {
                        if (this.ownerDocument instanceof XMLDocument) {
                            return undefined
                        } else {
                            let node = this.parentElement && this || this.parentNode;
                            let stylesheet_name = [node.closest("[xo-stylesheet]")].map(el => el && el.getAttribute("xo-stylesheet") || null)[0];
                            return stylesheet_name;
                        }
                    }
                });
            }

            XMLDocument.prototype.normalizeNamespaces = function () {
                let normalized = xdom.xml.normalizeNamespaces(this)
                this.documentElement.replace(normalized.documentElement)
                return this;
            }

            Element.prototype.remove = function () {
                let parentNode = this.parentNode;
                let parentElement = this.parentElement;
                var store = this.ownerDocument.store
                //this.ownerDocument.store = (this.ownerDocument.store || xdom.stores[xdom.data.hashTagName(this.ownerDocument)]) /*Se comenta para que quede el antecedente de que puede traer problemas de desempeño este enfoque. Nada grave*/
                if (store) { /*Asumimos que el store es administrado correctamente por la misma clase. Garantizar que se mantenga la referencia*/
                    store.takeSnapshot();
                }
                originalRemove.apply(this, arguments);
                let descriptor = Object.getPropertyDescriptor(this, 'parentNode') || { writable: true };
                if (descriptor.writable) {
                    Object.defineProperty(this, 'parentNode', { get: function () { return parentNode } }); //Si un elemento es borrado, pierde la referencia de parentElement y parentNode, pero con esto recuperamos cuando menos la de parentNode. La de parentElement no la recuperamos para que de esa forma sepamos que es un elemento que está desconectado. Métodos como "closest" dejan de funcionar cuando el elemento ya fue borrado.
                }
                if (this.ownerDocument.selectSingleNode && store) {
                    //let refresh = !parent.selectSingleNode('//@state:refresh');
                    //if (refresh) {
                    //store = (store || xdom.stores[xdom.data.hashTagName(this.ownerDocument)])
                    if (store) {
                        if (parentElement) {
                            //parentNode.setAttributeNS(xdom.xml.namespaces["state"], "state:refresh", "true");
                            ////parentNode = (parentNode.ownerDocument.store.find(parentNode) || parentNode); //Se quita para que la operación de borrado sólo ocurra en el documento actual
                            store.render();
                        } else {
                            delete xdom.stores[store.tag]
                        }
                    }
                    //}
                    //parentNode.setAttributeNS(null, "state:refresh", "true");
                    //parentNode.ownerDocument.store = (parentNode.ownerDocument.store || xdom.stores[xdom.data.hashTagName(parentNode.ownerDocument)]);
                    //parentNode.setAttributeNS(xdom.xml.namespaces["state"], "state:refresh", "true");
                    //return new Promise(resolve => {
                    //    setTimeout(() => {
                    //        xdom.stores.active.render();
                    //        resolve(true);
                    //    }, 50);
                    //});
                }
            }

            Element.prototype.setAttributes = async function (attributes, refresh, delay) {
                if (!attributes) return;
                if (!isNaN(parseInt(delay))) {
                    await xdom.delay(delay);
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
                                this.ownerDocument.store.render(); //xdom.stores.active.documentElement && xdom.stores.active.documentElement.setAttributeNS(xdom.xml.namespaces["state"], "state:refresh", "true");
                            } else if (this.ownerDocument && this.ownerDocument.selectSingleNode && this.ownerDocument.store) {
                                //this.setAttributeNS(xdom.xml.namespaces["state"], "state:refresh", "true");
                                this.ownerDocument.store.render();
                            }
                            return original_textContent.set.call(this, value);
                        } else {
                            return original_textContent.set.call(this, value);
                        }
                    }
                }
            );

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

            Object.defineProperty(Array.prototype, 'removeAll', {
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
            });

            var element_proxy = new Proxy(Node, {
                get: function (target, name) {
                    return target[name];
                },
                set: async function (target, name, value) {
                    let refresh;
                    if (value && ['object', 'function'].includes(typeof (value))) {
                        throw ('State value is not valid type');
                    }
                    if (target[name] != value) {
                        refresh = true
                    }
                    target[name] = value
                    var return_value
                    if (refresh) {
                        var name = name, value = value;
                        await self.library.load();
                        if ([...Object.values(self.library || {})].filter(stylesheet => {
                            return !!(stylesheet || window.document.createElement('p')).selectSingleNode(`//xsl:stylesheet/xsl:param[@name='state:${name}']`)
                        }).length) {
                            console.log(`Rendering ${document.tag} triggered by state:${name}`);
                            self.render(/*true*/);
                        };
                    }
                }
            })

            Element.prototype.setAttributeNS = function (namespace_URI, attribute, value, refresh = false) {
                if (!this.ownerDocument.store && attribute.indexOf(':') === -1) {
                    setAttributeNS_original.apply(this, arguments);
                    return;
                }
                let target = this;
                let { prefix, name: attribute_name } = xdom.xml.getAttributeParts(attribute);
                namespace_URI = namespace_URI || target.resolveNS(prefix) || xdom.xml.namespaces[prefix]
                let old_value = target.getAttributeNS(namespace_URI, attribute);
                value = typeof value === 'function' && value.call(this) || value && value.constructor === {}.constructor && JSON.stringify(value) || value;
                if (old_value !== value && target.ownerDocument.store) {
                    if (xdom.tracking.attributes.includes(attribute) || xdom.tracking.prefixes.includes(prefix)) {
                        target.ownerDocument.store.takeSnapshot()
                        if (!target.resolveNS("initial")) {
                            setAttributeNS_original.call(target.ownerDocument.documentElement, xdom.xml.namespaces["xmlns"], "xmlns:initial", xdom.xml.namespaces["initial"]);
                        }
                        if (target.getAttribute(`initial:${attribute_name}`) == null) {
                            setAttributeNS_original.call(target, xdom.xml.namespaces["initial"], "initial:" + attribute_name, old_value || "");
                        }
                    }
                    if (xdom.tracking.attributes.includes(attribute) || xdom.tracking.prefixes.includes(prefix)) {
                        if (!target.resolveNS("prev")) {
                            setAttributeNS_original.call(target.ownerDocument.documentElement, xdom.xml.namespaces["xmlns"], "xmlns:prev", xdom.xml.namespaces["prev"]);
                        }
                        setAttributeNS_original.call(target, xdom.xml.namespaces["prev"], "prev:" + attribute_name, (old_value || ""));
                    }
                    if (!target.resolveNS("state")) {
                        setAttributeNS_original.call(target.ownerDocument.documentElement, xdom.xml.namespaces["xmlns"], "xmlns:state", xdom.xml.namespaces["state"]);
                    }

                    if (value === undefined) {
                        target.removeAttribute(attribute, refresh);
                    } else {
                        setAttributeNS_original.call(target, namespace_URI, attribute, value);
                    }

                    if (prefix) {
                        window.top.dispatchEvent(new xdom.listener.Event(`${prefix}Changed`, { node: target, prefix: prefix, attribute: attribute_name, new: value, old: old_value }));
                    }
                    window.top.dispatchEvent(new xdom.listener.Event('attributeChanged', { node: target, attribute: attribute, value: value, old_value: old_value }));
                    if (refresh) {
                        target.store.render(((event || {}).target || {}).stylesheet);
                    }
                } else {
                    setAttributeNS_original.call(target, namespace_URI, attribute, value);
                }
            }

            var getAttribute_original = Element.prototype.getAttribute;

            Element.prototype.getAttribute = function (attribute) {
                if (this.ownerDocument && this.ownerDocument.store) {
                    attribute = attribute.replace(/^@/, "");
                }
                return getAttribute_original.call(this, attribute);
            }
            Element.prototype.get = Element.prototype.getAttribute;

            Element.prototype.attr = function () {
                return this.getAttribute.apply(this, arguments)
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

            Element.prototype.setAttribute = async function (attribute, value, refresh = true, delay) {
                if (this.ownerDocument && this.ownerDocument.store) {
                    attribute = attribute.replace(/^@/, "");
                }
                let target = (this.ownerDocument && this.ownerDocument.store && this.ownerDocument.store.find(this) || this);
                target.setAttributeNS(undefined, attribute, value, refresh);
                if (target !== this) {
                    this.setAttributeNS(undefined, attribute, value, false);
                }
            }
            Element.prototype.set = Element.prototype.setAttribute

            xdom.listener.on('attributeChanged', function ({ node: target, attribute, value, oldValue }) {
            })

            Element.prototype.removeAttribute = function (attribute, refresh) {
                if (this.ownerDocument.selectSingleNode && this.ownerDocument.store) {
                    //if (attribute != 'state:refresh' && ((xdom.manifest.server || {}).endpoints || {}).login && !(xdom.session.status == 'authorized')) {
                    //    return;
                    //}
                    let { prefix, name: attribute_name } = xdom.xml.getAttributeParts(attribute);
                    var refresh = Array.prototype.coalesce(refresh, !(["xml", "xmlns"].includes(prefix) || attribute == 'state:refresh'));
                    originalRemoveAttribute.apply(this, arguments);
                    if (refresh) {
                        this.ownerDocument.store.render(refresh);
                    }
                } else {
                    originalRemoveAttribute.apply(this, arguments);
                }
            }

            Attr.prototype.selectSingleNode = function (cXPathString) {
                if (this.ownerDocument.selectSingleNode) {
                    return this.ownerDocument.selectSingleNode(cXPathString, this);
                }
                else {
                    throw "For XML Elements Only";
                }
            }

            Attr.prototype.set = function (value) {
                return this.value = value
            }

            let original_ProcessingInstruction_remove = ProcessingInstruction.prototype.remove;
            ProcessingInstruction.prototype.remove = function (refresh) {
                original_ProcessingInstruction_remove.apply(this, arguments);
                if (this.ownerDocument && this.ownerDocument.store) {
                    [document.querySelector(`[xo-store="${this.ownerDocument.store.tag}"][xo-stylesheet='${xdom.json.fromAttributes(this.textContent)["href"]}']`)].map(el => el && el.remove());
                    this.ownerDocument.store.render(refresh);
                }
            }

            ProcessingInstruction.prototype.replaceBy = function (new_element) {
                this.parentNode.insertBefore(new_element, this);
                original_ProcessingInstruction_remove.apply(this, arguments);
                //if (this.ownerDocument && this.ownerDocument.store) { //TODO: Revisar si es necesario renderear
                //    this.ownerDocument.store.render(Array.prototype.coalesce(refresh, false));
                //}
            }

            Attr.prototype.remove = function (refresh) {
                var refresh = Array.prototype.coalesce(refresh, true);
                if (this.ownerDocument.selectSingleNode) {
                    let ownerElement = this.ownerElement;
                    if (ownerElement) {
                        return ownerElement.removeAttribute(this.name, refresh);
                    }
                }
                else {
                    throw "For XML Attributes Only";
                }
            }

            Element.prototype.getNamespaces = function () {
                if (this instanceof HTMLElement) {
                    return {};
                } else {
                    var xsltProcessor = new XSLTProcessor();
                    xsltProcessor.importStylesheet(xdom.xml.createDocument(`
                <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:source="http://panax.io/fetch/request">
                  <xsl:output method="xml" indent="no" omit-xml-declaration="yes"/>
                  <xsl:template match="*" priority="-1">
                    <output>
                        <xsl:for-each select="current()/namespace::*">
                            <xsl:variable name="current-namespace" select="."/>
                            <xsl:variable name="prefix" select="name(.)"/>
                            <xsl:if test=".!='http://www.w3.org/XML/1998/namespace'">
                              <xsl:value-of select="concat(' ','xmlns')"/>
                              <xsl:if test="name(.)!=''">
                                <xsl:value-of select="concat(':',name(.))"/>
                              </xsl:if>
                              <xsl:text>="</xsl:text>
                              <xsl:value-of select="." disable-output-escaping="yes"/>
                              <xsl:text>"</xsl:text>
                            </xsl:if>
                        </xsl:for-each>
                    </output>
                  </xsl:template>
                </xsl:stylesheet>
                `));
                    try {
                        return JSON.parse('{' + xsltProcessor.transformToDocument(this).documentElement.textContent.replace(/(xmlns)=(["'])([^\2]+?)\2/ig, '').replace(/xmlns:(\w+)=(["'])([^\2]+?)\2/ig, ',"$1":$2$3$2').replace(/^[\s,]+/, '') + '}');
                    } catch (e) {
                        return {}
                    }

                }
            }

            Element.prototype.selectNodes = function (cXPathString) {
                if (this.ownerDocument.selectNodes) { return this.ownerDocument.selectNodes(cXPathString, this); }
                //else {
                //    throw "For XML Elements Only";
                //}
            }
            Element.prototype.selectAll = Element.prototype.selectNodes

            Element.prototype.selectSingleNode = function (cXPathString) {
                if (this.ownerDocument.selectSingleNode) {
                    return this.ownerDocument.selectSingleNode(cXPathString, this);
                }
                //else {
                //    throw "For XML Elements Only";
                //}
            }
            //Element.prototype.selectFirst = Element.prototype.selectSingleNode
            Element.prototype.select = Element.prototype.selectSingleNode

            var insertBefore = Element.prototype.insertBefore
            Element.prototype.insertBefore = function (new_node) {
                if ((this.ownerDocument || this) instanceof XMLDocument) {
                    //if (((xdom.manifest.server || {}).endpoints || {}).login && !(xdom.session.status == 'authorized')) {
                    //    return;
                    //}
                    insertBefore.apply(this, arguments);
                    if (this.selectSingleNode(`//xsl:comment/text()[contains(.,'Session stylesheet')]`)) {
                        /*Update of session variables*/
                        let attribute = new_node;
                        Object.values(xdom.stores).map(store => {
                            (store.documentElement || document.createElement("p")).setAttribute(attribute.getAttribute("name"), attribute.textContent.replace(/[\s]+$/, ''));
                        });
                    }
                    if (this.ownerDocument.store) {
                        this.ownerDocument.store.render();
                    }
                } else {
                    insertBefore.apply(this, arguments);
                }
            }

            Node.prototype.replaceChild = function (new_node, target, refresh = true) {
                new_node = (new_node.documentElement || new_node);
                if ((this.ownerDocument || this) instanceof XMLDocument) {
                    let store = this.store;
                    //if (((xdom.manifest.server || {}).endpoints || {}).login && !(xdom.session.status == 'authorized')) {
                    //    return;
                    //}
                    ////var refresh = (refresh ?? !!xdom.stores.getActive()[this.ownerDocument.store.tag]);
                    //this.ownerDocument.documentElement.setAttributeNS(xdom.xml.namespaces["state"], 'state:refresh', 'true', refresh);
                    let result = replaceChild_original.apply(this, [new_node, target]);
                    if (this.selectSingleNode(`//xsl:comment/text()[contains(.,'Session stylesheet')]`)) {
                        /*Update of session variables*/
                        let attribute = new_node;
                        Object.values(xdom.stores).map(store => {
                            (store.documentElement || document.createElement("p")).setAttribute(attribute.getAttribute("name"), attribute.textContent.replace(/[\s]+$/, ''));
                        });
                    }
                    if (refresh && store) store.render()
                    return new_node;
                } else {
                    replaceChild_original.apply(this, [new_node, target]);
                    return new_node;
                }
            }

            Node.prototype.replace = function (new_node) {
                new_node = (new_node.documentElement || new_node)
                return this.parentNode.replaceChild(new_node.cloneNode(true), this);
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
                        throw ('Invalid option')
                }
            }

            Node.prototype.duplicate = function (reseed = true) {
                let new_node = this.cloneNode(true);
                this.appendAfter(new_node);
                if (reseed) {
                    new_node = new_node.reseed();
                }
                return new_node;
            }

            XMLDocument.prototype.reseed = function () {
                this.documentElement && this.documentElement.reseed();
                return this;
            }

            Element.prototype.reseed = function () {
                //if (navigator.userAgent.indexOf("Safari") == -1) {
                //    this = xdom.xml.transform(this, "xdom/normalize_namespaces.xslt");
                //}
                this.$$(`descendant-or-self::*[not(@x:id)]`).setAttributeNS('x:id', (function () { return `${this.nodeName}_${xdom.cryptography.generateUUID()}`.replace(/[:-]/g, '_') }));
                return this;

                let xsl = xdom.xml.createDocument(`
    <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:x="http://panax.io/xdom">
	    <xsl:key name="xid" match="*" use="@x:id" />
	    <xsl:template match="*|processing-instruction()|comment()|text()">
		    <xsl:copy>
			    <xsl:copy-of select="@*"/>
			    <xsl:apply-templates/>
		    </xsl:copy>
	    </xsl:template>
	    <xsl:template match="*[not(@x:id) or @x:id and count(key('xid',@x:id)[1] | .)=1]">
		    <xsl:copy>
			    <xsl:copy-of select="@*"/>
                <xsl:attribute name="x:id">
                  <xsl:value-of select="concat(translate(name(),':','_'),'_',generate-id())"/>
                </xsl:attribute>
			    <xsl:apply-templates/>
		    </xsl:copy>
	    </xsl:template>
    </xsl:stylesheet>
    `)
                return this.replace(this.transform(xsl));
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
                        if (xml_document instanceof Promise) {
                            return xml_document.then((document) => self.transform(document));
                        }
                        if (typeof (xml_document) == "string") {
                            let xsl = xml_document;
                            if (xsl in xdom.library) {
                                xml_document = xdom.library[xsl];
                            } else if (xsl in xdom.library.defaults) {
                                xml_document = xdom.library.defaults[xsl];
                            } else {
                                if (xdom.browser.isIphone()) { //Probablemente esto tiene que cambiar
                                    return this.transform(xdom.library.load(xsl));
                                    //(async () => {
                                    //    xdom.library[xsl] = await xdom.fetch.xml(xsl);
                                    //    xsl = xdom.library[xsl];
                                    //})();
                                } else {
                                    xml_document = xdom.xml.createDocument(`                          
                <xsl:stylesheet version="1.0"                        
                    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                    <xsl:import href="${xsl}" />
                </xsl:stylesheet>`);
                                }
                            }
                        }
                        if (xml_document && !((xml_document.ownerDocument || xml_document) instanceof XMLDocument)) {
                            throw ("Document must be a valid xml document.");
                        };
                        if (this.selectSingleNode('xsl:*') && !(xml_document && xml_document.selectSingleNode('xsl:*'))) {//Habilitamos opción para que un documento de transformación pueda recibir un documento para transformar (Proceso inverso)
                            return (xml_document || xdom.xml.createDocument(`<x:empty xmlns:x="http://panax.io/xdom"/>`)).transform(this);
                        }
                        let xsl = xml_document;
                        let xml = this.cloneNode(true);
                        var xmlDoc;
                        var result = undefined;
                        if (!xsl && ((arguments || {}).callee || {}).caller != Node.prototype.transform) {
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
                            throw ("XSL document is empty or invalid");
                        }
                        if (!xml.selectSingleNode("self::*|*|comment()") && xml.createComment) {
                            xml = xml.cloneNode(true);
                            xml.appendChild(xml.createComment("empty"))
                        }
                        xml.store = (this.ownerDocument || this).store;

                        if (document.implementation && document.implementation.createDocument) {
                            var xsltProcessor = new XSLTProcessor();
                            try {
                                if (navigator.userAgent.indexOf("Firefox") != -1) {
                                    var invalid_node = xsl.selectSingleNode("//*[contains(@select,'namespace::')]");
                                    if (invalid_node) {
                                        console.warn('There is an unsupported xpath in then file');
                                    }
                                }
                                if (navigator.userAgent.indexOf("iPhone") != -1 || xdom.debug["xdom.xml.consolidate"]) {
                                    xsl = xdom.xml.consolidate(xsl); //Corregir casos cuando tiene apply-imports
                                }

                                xsltProcessor.importStylesheet(xsl);
                                xsl.selectNodes(`//xsl:stylesheet/xsl:param[starts-with(@name,'js:')]`).filter(param => param.textContent).map(param => {
                                    try {
                                        xsltProcessor.setParameter(null, param.getAttribute("name"), eval(param.textContent))
                                    } catch (e) {
                                        //xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                                        console.error(e.message);
                                        xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                                    }
                                });
                                xsl.selectNodes(`//xsl:stylesheet/xsl:param[starts-with(@name,'session:')]`).map(param => {
                                    try {
                                        let param_name = param.getAttribute("name").split(":").pop();
                                        if (!(param_name in xdom.session)) xdom.session[param_name] = [eval(`(${param.textContent !== '' ? param.textContent : undefined})`), ''].coalesce();
                                        let session_value = xdom.session.getKey(param.getAttribute("name").split(/:/).pop());
                                        if (session_value !== undefined) {
                                            xsltProcessor.setParameter(null, param.getAttribute("name"), session_value);
                                        }
                                    } catch (e) {
                                        //xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                                        console.error(e.message);
                                    }
                                });
                                xsl.selectNodes(`//xsl:stylesheet/xsl:param[starts-with(@name,'state:')]`).map(param => {
                                    try {
                                        let state_value = xdom.stores.active.state[param.getAttribute("name").split(/:/).pop()];
                                        if (state_value !== undefined) {
                                            xsltProcessor.setParameter(null, param.getAttribute("name"), state_value);
                                        }
                                    } catch (e) {
                                        //xsltProcessor.setParameter(null, param.getAttribute("name"), "")
                                        console.error(e.message);
                                    }
                                });

                                ////if (!xml.documentElement) {
                                ////    xml.appendChild(xdom.xml.createDocument(`<x:empty xmlns:x="http://panax.io/xdom"/>`).documentElement)
                                ////}
                                if (xsl.selectSingleNode('//xsl:param[@name="debug:timer" and text()="true"]')) {
                                    console.time();
                                }
                                if (xsl.documentElement.getAttribute("xmlns") && !(xsl.selectSingleNode('//xsl:output[@method="html"]')) /*xdom.browser.isIOS()*/) {// && ((result || {}).documentElement || {}).namespaceURI == "http://www.w3.org/1999/xhtml" ) {
                                    let transformed = xsltProcessor.transformToFragment(xml, document);
                                    var newDoc;
                                    //if (transformed.children.length && transformed.firstElementChild.namespaceURI == "http://www.w3.org/1999/xhtml") {
                                    //newDoc = document.implementation.createDocument("http://www.w3.org/1999/xhtml", "html", null);
                                    //} else {
                                    //}

                                    if (transformed && transformed.children.length > 1) {
                                        newDoc = document.implementation.createDocument("http://www.mozilla.org/TransforMiix", "result", null);
                                        [...transformed.children].map(el => newDoc.documentElement.append(el))
                                    } else {
                                        newDoc = document.implementation.createDocument("http://www.w3.org/XML/1998/namespace", "", null);
                                        if (transformed && transformed.firstElementChild) {
                                            newDoc.append(transformed.firstElementChild)
                                        }
                                    }
                                    result = newDoc;
                                } else {
                                    result = xsltProcessor.transformToDocument(xml);
                                }
                                [...result.children].map(el => el instanceof HTMLElement && el.$$('//@*[starts-with(., "`") and substring(., string-length(.))="`"]').map(val => { try { val.value = eval(val.value.replace(/\$\{\}/g, '')) } catch (e) { console.log(e) } }));
                                if (!(result && result.documentElement) && !xml.documentElement) {
                                    xml.appendChild(xdom.xml.createNode(`<x:empty xmlns:x="http://panax.io/xdom"/>`))
                                    return xml.transform("empty.xslt");
                                }
                                if (xsl.selectSingleNode('//xsl:param[@name="debug:timer" and text()="true"]')) {
                                    console.timeEnd();
                                }
                            } catch (e) {
                                let default_document = xdom.library.defaults[(xsl.selectSingleNode("//xsl:import") || document.createElement('p')).getAttribute("href")];
                                if (default_document && arguments.callee.caller != xdom.xml.transform) {
                                    result = xml.transform(default_document);
                                } else if (!xml.documentElement) {
                                    return xml;
                                } else {
                                    console.error("xdom.xml.transform: " + (e.message || e.name || e)); //TODO: No está entrando en esta parte, por ejemplo cuando hay un error 404. net::ERR_ABORTED 404 (Not Found)
                                    return xml;
                                }
                            }
                            if (!result) {
                                if (((arguments || {}).callee || {}).caller != xdom.xml.transform && xsl.selectSingleNode('//xsl:import[@href="login.xslt"]')) {
                                    result = xml.transform(xdom.library.defaults["login.xslt"]);
                                } else if (((arguments || {}).callee || {}).caller != xdom.xml.transform && xsl.selectSingleNode('//xsl:import[@href="shell.xslt"]')) {
                                    result = xml.transform(xdom.library.defaults["shell.xslt"]);
                                } else if (!xml.documentElement) {
                                    return xml;
                                } else {
                                    throw (xdom.messages.transform_exception || "There must be a problem with the transformation file. A misplaced attribute, maybe?"); //Podría ser un atributo generado en un lugar prohibido. Se puede enviar al servidor y aplicar ahí la transformación //TODO: Hacer una transformación del XSLT para identificar los problemas comúnes.
                                    result = xml;
                                }
                            }
                            else if (typeof (result.selectSingleNode) == "undefined" && result.documentElement) {
                                result = xdom.xml.createDocument(result.documentElement);
                            }
                            [...result.querySelectorAll('parsererror div')].map(message => {
                                if (String(message.textContent).match(/prefix|prefijo/)) {
                                    var prefix = (message.textContent).match(/(?:prefix|prefijo)\s+([^\s]+\b)/).pop();
                                    if (!xdom.xml.namespaces[prefix]) {
                                        var message = xdom.data.createMessage(message.textContent.match("(error [^:]+):(.+)").pop());
                                        xml.documentElement.appendChild(message.documentElement);
                                        return xml;
                                    }
                                    (xml.documentElement || xml).setAttributeNS('http://www.w3.org/2000/xmlns/', "xmlns:" + prefix, xdom.xml.namespaces[prefix]);
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
                            if (((arguments || {}).callee || {}).caller != xdom.xml.transform) {
                                window.top.dispatchEvent(new xdom.listener.Event('xmlTransformed', { original: xml, transformed: result }));
                            }
                        } catch (e) { }
                        return result
                    },
                    writable: false, enumerable: false, configurable: false
                });
            }

            if (!XMLDocument.prototype.hasOwnProperty('tag')) {
                Object.defineProperty(XMLDocument.prototype, 'tag', {
                    get: function () {
                        return this.store && this.store.tag || "";//xdom.stores.active.tag;
                    }
                });
            }

            if (!Document.prototype.hasOwnProperty('render')) {
                Object.defineProperty(Document.prototype, 'render', {
                    value: async function () {
                        let _applyScripts = function (targetDocument, scripts = []) {
                            for (let script of scripts) {
                                if (script.selectSingleNode(`self::*[self::xhtml:script[@src] or self::xhtml:link[@href] or self::xhtml:meta][not(text())]`)) {
                                    if (![...targetDocument.querySelectorAll(script.tagName)].filter(node => node.isEqualNode(script)).length) {
                                        var new_element = targetDocument.createElement(script.tagName);
                                        [...script.attributes].map(attr => new_element.setAttributeNS(null, attr.name, attr.value));
                                        new_element.textContent = script.textContent;

                                        if (new_element.tagName.toLowerCase() == "script") {
                                            new_element.onload = function () {
                                                console.log("Script is loaded");
                                            };
                                        }
                                        targetDocument.head.appendChild(new_element);
                                    }
                                } else if (!script.getAttribute("src") && script.textContent) {
                                    script.textContent = xdom.string.htmlDecode(script.textContent); //Cuando el método de output es html, algunas /entidades /se pueden codificar. Si el output es xml las envía corregidas
                                    if (script.hasAttribute("defer") || script.hasAttribute("async") || script.selectSingleNode(`self::xhtml:style`)) {
                                        if (![...targetDocument.documentElement.querySelectorAll(script.tagName)].find(node => node.isEqualNode(script))) {
                                            targetDocument.documentElement.appendChild(script);
                                        }
                                    } else {
                                        try {
                                            //console.clear() //console.log(script.textContent)
                                            eval(script.textContent);
                                        } catch (message) {
                                            console.error(message)
                                        }
                                    }
                                } else {
                                    throw (`A script couldn't be loaded.`)
                                }
                            }
                        }
                        _applyScripts(window.document, this.body.querySelectorAll("script, style"))
                        window.document.body.replaceWith(this.body)
                    }
                });
            }

            if (!XMLDocument.prototype.hasOwnProperty('render')) {
                Object.defineProperty(XMLDocument.prototype, 'render', {
                    value: async function (stylesheets) {
                        xdom.state.save() //TODO: Reubicar a un posición en donde se optimice más su uso, por ejemplo al scroll
                        let last_argument = [...arguments].pop();
                        let options = last_argument && typeof (last_argument) == 'object' && last_argument.constructor === {}.constructor && last_argument || undefined;
                        stylesheets = stylesheets !== options && stylesheets || this.stylesheets;
                        stylesheets = stylesheets instanceof Array && stylesheets || stylesheets && [stylesheets] || [];
                        let self = this;
                        let tag = self.tag;
                        if (this.selectSingleNode('xsl:*')) {//Habilitamos opción para que un documento de transformación pueda recibir un documento para transformar (Proceso inverso)
                            options = options || {};
                            options["target"] = options["target"] || document.querySelector(`[xo-store="${options["document"] && options["document"].tag || options["document"] || tag}"]`);
                            this.copyPropertiesFrom(options);
                            return (options["document"] || xdom.xml.createDocument(`<x:empty xmlns:x="http://panax.io/xdom"/>`)).render(this);
                        }
                        var data = this.cloneNode(true);
                        data.selectNodes('//x:r[position()>600 and @value!=../../@value]').remove(false);

                        //if (!stylesheets.length) { //Ver a dónde mandamos este failover
                        //    stylesheets.push({
                        //        href: "shell.xslt"
                        //        , target: "body"
                        //        , role: "shell"
                        //    });
                        //}
                        let action;
                        let stylesheet_target = 'body';
                        //const isSelectorValid = ((dummyElement) =>
                        //    (selector) => {
                        //        if (!selector) return false;
                        //        try { selector && dummyElement.querySelector(selector) } catch { return false }
                        //        return true;
                        //    })(document.createDocumentFragment())
                        //    ;
                        //const isXPath = ((dummyElement) =>
                        //    (selector) => {
                        //        if (!selector) return false;
                        //        try { !!dummyElement.selectNodes(selector) } catch { return false }
                        //        return true;
                        //    })((data.documentElement || data).cloneNode(false))
                        //    ;
                        for (let stylesheet of stylesheets.filter(stylesheet => stylesheet.role != "init" && stylesheet.role != "binding")) {
                            //data.store = self.store;
                            let xsl = stylesheet instanceof XMLDocument && stylesheet || await stylesheet.document || stylesheet.href;
                            action = (stylesheet.action || !stylesheet.target && "append" || action);
                            if ((stylesheet.target || '').match(/^self::./)) {//if (stylesheet.target && !isSelectorValid(stylesheet.target) && isXPath(stylesheet.target)) {
                                let i = 0;
                                let dom = data;
                                if (dom.documentElement && !dom.documentElement.selectSingleNode(stylesheet.target)) continue;
                                do {
                                    data.selectNodes("//@binding:changed").remove(false);
                                    ++i;
                                    dom = data.transform(xsl);
                                    //if (!(dom.documentElement.namespaceURI && dom.documentElement.namespaceURI.indexOf("http://www.w3.org") != -1)) {
                                    data = dom;
                                    //}
                                } while (i < 15 && dom.documentElement.selectSingleNode(stylesheet.target) && (!xsl.documentElement.resolveNS('binding') || dom.selectSingleNode("//@binding:changed")));
                                data.selectNodes("//@binding:changed").remove(false);
                                continue;
                            }
                            stylesheet_target = stylesheet.target instanceof HTMLElement && stylesheet.target || document.querySelector(stylesheet.target || stylesheet_target);
                            if (!stylesheet_target) {
                                if (!(stylesheet.dependencies || {}).length) {
                                    continue;
                                }
                                let dependencies = stylesheet.dependencies.map(parent_tag => parent_tag != tag && xdom.stores[parent_tag] || undefined).filter(store => store).map(store => store.render());
                                await Promise.all(dependencies);
                                stylesheet_target = stylesheet.target instanceof HTMLElement && stylesheet.target || document.querySelector(stylesheet.target || stylesheet_target);
                                if (!stylesheet_target) {
                                    throw (`Couldn't render store ${store.tag}`);
                                }
                            }
                            stylesheet_target = tag && stylesheet_target.queryChildren(`[xo-store='${tag}'][xo-stylesheet='${stylesheet.href}']`)[0] || !tag && (`[xo-stylesheet="${stylesheet.href}"]:not([xo-store])`) || stylesheet_target;
                            if (stylesheet_target.matches(`[xo-stylesheet="${stylesheet.href}"]:not([xo-store])`)) {
                                action = 'replace';
                            } else if (!action && stylesheet_target.matches(`[xo-store='${tag}']:not([xo-stylesheet])`)) {
                                action = 'append';
                            } else if (stylesheet_target.matches(`[xo-store='${tag}'][xo-stylesheet='${stylesheet.href}']`)) {
                                action = 'replace';
                            } else if (stylesheet_target.matches(`[xo-store='${tag}'][xo-stylesheet]`)) {
                                continue;
                            }
                            target = stylesheet_target;
                            if (target === document.body && action === 'replace') {
                                action = null;
                            }

                            if (!stylesheet.href) {
                                console.warn(`There's a missing href in a processing-instruction`)
                            }
                            //let dom = xdom.xml.transform(data, (this.library[stylesheet.href] || xdom.library[stylesheet.href] || !(document.querySelector(`[xo-store]`)) && (xdom.library.defaults[stylesheet.href] || xdom.library.defaults["shell.xslt"]) || xdom.library.defaults[stylesheet.href] || stylesheet.href));
                            let dom = data.transform(xsl);
                            if (!(dom && dom.documentElement)) { continue; }
                            if (((dom.documentElement || {}).namespaceURI || "").indexOf("http://www.mozilla.org/TransforMiix") != -1) {
                                // TODO: Revisar esta parte
                                data.selectNodes(`processing-instruction('xml-stylesheet')`).remove();
                                if (!this.library[stylesheet.href]) {
                                    dom = data.transform(xdom.library[stylesheet.href] || xdom.library.defaults[stylesheet.href] || xdom.library.defaults["shell.xslt"]);
                                } else {
                                    dom = data.transform(this.library[stylesheet.href]);
                                }
                            }
                            if (!(dom.documentElement.namespaceURI && dom.documentElement.namespaceURI.indexOf("http://www.w3.org") != -1)) {
                                data = dom;
                            }
                            let scripts_external, scripts;

                            let _applyScripts = function (targetDocument, scripts = []) {
                                for (let script of scripts) {
                                    if (script.selectSingleNode(`self::*[self::xhtml:script[@src] or self::xhtml:link[@href] or self::xhtml:meta][not(text())]`)) {
                                        if (![...targetDocument.querySelectorAll(script.tagName)].filter(node => node.isEqualNode(script)).length) {
                                            var new_element = targetDocument.createElement(script.tagName);
                                            [...script.attributes].map(attr => new_element.setAttributeNS(null, attr.name, attr.value));
                                            new_element.textContent = script.textContent;

                                            if (new_element.tagName.toLowerCase() == "script") {
                                                new_element.onload = function () {
                                                    console.log("Script is loaded");
                                                };
                                            }
                                            targetDocument.head.appendChild(new_element);
                                        }
                                    } else if (!script.getAttribute("src") && script.textContent) {
                                        script.textContent = xdom.string.htmlDecode(script.textContent); //Cuando el método de output es html, algunas /entidades /se pueden codificar. Si el output es xml las envía corregidas
                                        if (script.hasAttribute("defer") || script.hasAttribute("async") || script.selectSingleNode(`self::xhtml:style`)) {
                                            if (![...targetDocument.documentElement.querySelectorAll(script.tagName)].find(node => node.isEqualNode(script))) {
                                                targetDocument.documentElement.appendChild(script);
                                            }
                                        } else {
                                            try {
                                                //console.clear() //console.log(script.textContent)
                                                eval(script.textContent);
                                            } catch (message) {
                                                console.error(message)
                                            }
                                        }
                                    } else {
                                        throw (`A script couldn't be loaded.`)
                                    }
                                }
                            }
                            //let styles = document.head.appendChild(await xdom.library.load("styles.css"));
                            scripts_external = dom.selectNodes('//*[self::xhtml:script[@src or @defer or @async or not(text())] or self::xhtml:link[@href] or self::xhtml:meta][not(text())]').removeAll();
                            _applyScripts(document, scripts_external);
                            if (!target) {
                                if (xdom.debug.enabled) {
                                    if (stylesheet_target) {
                                        throw (`No existe la ubicación "${stylesheet_target}"`);
                                    }
                                }
                                let missing_stores = []
                                let active_tags = xdom.state.activeTags();
                                active_tags.filter(_tag => tag != _tag && xdom.stores[_tag] && !xdom.stores[_tag].isRendered).map(async _tag => {
                                    let store = xdom.stores[_tag];
                                    if (store) {
                                        missing_stores.push(store.render(/*true*/));
                                    }
                                });
                                await Promise.all(missing_stores);
                                self.render();
                                //self.isActive = false;
                                continue;
                            } else if (dom.documentElement.tagName.toLowerCase() == "html") {
                                //dom.documentElement.namespaceURI == "http://www.w3.org/1999/xhtml"
                                //target = document.body;
                                xdom.dom.setEncryption(dom, 'UTF-7');
                                let iframe;
                                if (document.activeElement.tagName.toLowerCase() == 'iframe') {
                                    iframe = document.activeElement;
                                    target = (document.activeElement || {}).contentDocument.querySelector('main,table,div,span');
                                    target.parentElement.replaceChild(dom.querySelector(target.tagName.toLowerCase()), target);
                                    //if ((dom.documentElement || dom).selectNodes) { //(dom.documentElement instanceof XMLDocument) {
                                    //    _applyScripts((document.activeElement || {}).contentDocument, dom);
                                    //}
                                } else {
                                    xdom.dom.clear(target);
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
                                        Object.entries(xdom.listener).map(([event_name, handler]) => iframe.addEventListener(event_name, handler));
                                        //iframe.addEventListener('focusout', xdom.listeners.dom.onfocusout);
                                        //iframe.addEventListener('change', xdom.listeners.dom.onchange);
                                    }
                                    var url = xdom.dom.getGeneratedPageURL({
                                        html: xdom.string.htmlDecode((dom.documentElement || dom).outerHTML),
                                        css: (dom.querySelector('style') || {}).innerHTML,
                                        js: `var xdom = (xdom || parent.xdom); document.xdom_global_refresh_disabled=true; let iframe=parent.document.querySelector('iframe'); iframe.height=document.querySelector('body').scrollHeight+10; iframe.width=document.querySelector('body').scrollWidth+10; xdom.modernize(iframe.contentWindow); document.querySelector('body').setAttributeNS(null, "xo-store", '${tag}');` //+ js//((dom.querySelector('script') || {}).innerHTML || "")
                                        //window.top.document.querySelector('body').setAttributeNS(null, "xo-store", window.top.location.hash)
                                    });
                                    iframe.src = url;
                                }
                                target = iframe;
                                xdom.state.restore(target);
                            } else if (!(dom.documentElement.namespaceURI && dom.documentElement.namespaceURI.indexOf("http://www.w3.org") != -1)) {
                                dom = await dom.transform('error.xslt');
                                target = document.querySelector('main') || document.querySelector('body')
                                if (stylesheet.action == "replace") {
                                    target = target.replace(dom);
                                } else {
                                    xdom.dom.clear(target);
                                    target.append(...dom.cloneNode(true).childNodes);
                                }
                            } else {
                                scripts = dom.selectNodes('//*[self::xhtml:script]').removeAll();

                                (dom.documentElement || dom).setAttributeNS(null, "xo-store", tag);
                                (dom.documentElement || dom).setAttributeNS(null, "xo-stylesheet", stylesheet.href);
                                if (action == "replace") {
                                    target = target.replace(dom);
                                } else if (action == "append") {
                                    target.append(dom.documentElement || dom);
                                } else {
                                    xdom.dom.clear(target);
                                    target.append(...dom.cloneNode(true).childNodes);
                                }

                                var lines = document.querySelectorAll(".leader-line")
                                for (let l = 0; l < lines.length; ++l) {
                                    lines[l].remove();
                                }
                                if ((dom.documentElement || dom).selectNodes) { //(dom.documentElement instanceof XMLDocument) {
                                    _applyScripts(document, scripts.filter((script, index, arr) => {
                                        script = script.selectSingleNode('self::*[not(@defer or @async)]');
                                        if (script) arr.splice(index, 1);
                                        return script;
                                    }));
                                }
                                xdom.state.restore(dom);
                            }
                            [...target.querySelectorAll('img')].map(el => el.addEventListener('error', function () {
                                window.top.dispatchEvent(new xdom.listener.Event('error', { event: event }));
                            }));
                            [...target.querySelectorAll('[xo-attribute],input[type="file"]')].map(el => el.addEventListener('change', async function () {
                                let _attribute = this.getAttribute("xo-attribute");
                                let source = this.source;
                                if (this.type.toLowerCase() === 'file') {
                                    if (!(this.files && this.files[0])) return;
                                    let store = await xdom.database.files;
                                    store.add(this.files).forEach(record => {
                                        [...this.ownerDocument.querySelectorAll(`*[for="${this.id}"] img`)].forEach(img => img.src = record.uid);
                                        if (_attribute) {
                                            let { prefix, name: attribute_name } = xdom.xml.getAttributeParts(_attribute);
                                            source = source.nodeType == 2 ? source.$('..') : source;
                                            let metadata = Object.assign({}, xdom.string.getFileParts(record.saveAs), record, { name: record.file["name"], type: record.file["type"] });
                                            delete metadata["file"];
                                            source.set(_attribute, record.uid);
                                            source.set(`metadata:${attribute_name}`, metadata);
                                        }
                                    });
                                } else if (source instanceof Attr) {
                                    source.set(this.value);
                                } else if (source instanceof Node) {
                                    source.set(_attribute, this.value);
                                }
                            }))
                            if (window.MathJax) {
                                MathJax.typeset && MathJax.typeset();
                            } else if (dom.selectSingleNode('//mml:math') || ((dom.documentElement || {}).textContent || '').match(/(?:\$\$|\\\(|\\\[|\\begin\{.*?})/)) { //soporte para MathML
                                if (!window.MathJax) {
                                    window.MathJax = {
                                        loader: { load: ['[mml]/mml3'] }
                                    }
                                }
                                let script = document.createElement('script');
                                script.src = 'https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-chtml.js';
                                document.head.appendChild(script);
                            }

                            let unbound_elements = dom.querySelectorAll('[xo-source=""],[xo-scope=""]');
                            if (unbound_elements.length) {
                                console.warn(`There are ${unbound_elements.length} disconnected element${unbound_elements.length > 1 ? 's' : ''}`)
                            }

                            _applyScripts(document, scripts);
                            /*TODO: Mover este código a algún script diferido*/
                            [...(target && target.ownerDocument.querySelectorAll('[data-bs-toggle="tooltip"]') || [])].map(function (tooltipTriggerEl) {
                                return new bootstrap.Tooltip(tooltipTriggerEl)
                            })
                        }
                        return Promise.resolve(this);
                    },
                    writable: false, enumerable: false, configurable: false
                });
            }

            var appendChild_original = Element.prototype.appendChild
            Element.prototype.appendChild = function (new_node, refresh) {
                if (!(new_node instanceof Node)) throw ("Element to be added is not a valid Node");
                let self = (this.ownerDocument && this.ownerDocument.store && this.ownerDocument.store.find(this) || this);
                if (!(self.ownerDocument instanceof XMLDocument)) {
                    return appendChild_original.apply(self, [...arguments]);
                }
                refresh = Array.prototype.coalesce(refresh, true);
                if (refresh && new_node && self.ownerDocument.store /*self.ownerDocument.documentElement.selectSingleNode('//@x:id')*/) {
                    new_node = new_node.reseed();
                    var refresh = Array.prototype.coalesce(refresh, true);
                    //if (refresh && !(self.namespaceURI && self.namespaceURI.indexOf('www.w3.org') != -1)) {
                    //    self.ownerDocument.documentElement.setAttributeNS(xdom.xml.namespaces["state"], 'state:refresh', 'true');
                    //}
                    appendChild_original.apply(self, [new_node]);
                    //xdom.delay(50).then(() => {
                    self.ownerDocument.store.render(refresh);
                    //});
                } else {
                    return appendChild_original.apply(self, arguments);
                }
            }

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

xdom.modernize();

xdom.dom.toExcel = (function () {
    //from https://stackoverflow.com/questions/17142427/javascript-to-export-html-table-to-excel
    var uri = 'data:application/vnd.ms-excel;base64,'
        , template = '<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40"><head><!--[if gte mso 9]><xml><x:ExcelWorkbook><x:ExcelWorksheets><x:ExcelWorksheet><x:Name>{worksheet}</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet></x:ExcelWorksheets></x:ExcelWorkbook></xml><![endif]--><meta http-equiv="content-type" content="text/plain; charset=UTF-8"/></head><body><table>{table}</table></body></html>'
        , base64 = function (s) { return window.btoa(unescape(encodeURIComponent(s))) }
        , format = function (s, c) { return s.replace(/{(\w+)}/g, function (m, p) { return c[p]; }) }
    return function (table, name) {
        if (!table.nodeType) table = document.getElementById(table)
        table = table.cloneNode(true);
        [...table.querySelectorAll('.non_printable')].forEach(el => el.remove())
        var ctx = { worksheet: name || 'Worksheet', table: table.innerHTML }
        window.location.href = uri + base64(format(template, ctx))
    }
})();