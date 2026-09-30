/* XOver XSLT bootstrap. May also be included as an XHTML script in raw XML.
 * data-autoload="false" selects API-only mode (used by xo.js).
 */
(function () {
	if (window.xoverXsltReady) return;
	const script = document.currentScript;
	const autoload = script.getAttribute('data-autoload') !== 'false';
	const url = new URL('xslt-polyfill/xslt-polyfill.min.js', script.src);
	window.xoverXsltReady = new Promise((resolve, reject) => {
		let loader;
		const timer = setTimeout(() => finish(new Error(`XSLT polyfill timed out: ${url}`)), 30000);
		let settled = false;
		function finish(error) {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			if (loader) loader.onload = loader.onerror = null;
			if (error) reject(error); else resolve();
		}
		try {
			// Test a transformation, not just the presence of the constructor.
			let supported = false;
			try {
				const parser = new DOMParser();
				const processor = new XSLTProcessor();
				const xml = parser.parseFromString('<test/>', 'application/xml');
				processor.importStylesheet(parser.parseFromString('<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:param name="value"/><xsl:template match="/"><ok value="{$value}"/></xsl:template></xsl:stylesheet>', 'application/xml'));
				processor.setParameter(null, 'value', 'ready');
				supported = processor.transformToDocument(xml)?.documentElement?.getAttribute('value') === 'ready'
					&& processor.transformToFragment(xml, document)?.querySelector('ok')?.getAttribute('value') === 'ready';
			} catch (_) { /* Missing or disabled native implementation. */ }
			if (autoload && supported) return finish();
			// We already checked actual functionality, including disabled native APIs.
			window.xsltUsePolyfillOnlyIfNeeded = false;
			window.xsltDontAutoloadXmlDocs = true;
			loader = document.createElementNS('http://www.w3.org/1999/xhtml', 'script');
			loader.src = url.href;
			loader.charset = 'utf-8';
			if (script.nonce) loader.nonce = script.nonce;
			loader.onerror = () => finish(new Error(`Unable to load XSLT polyfill: ${url}`));
			loader.onload = () => {
				Promise.resolve().then(() => {
					if (typeof window.xsltPolyfillReady !== 'function') throw new Error('XSLT polyfill did not expose its readiness API');
					return window.xsltPolyfillReady();
				}).then(() => finish(), finish);
			};
			(document.head || document.documentElement).appendChild(loader);
		} catch (error) { finish(error); }
	});
	// Raw XML needs its own bootstrap: xo.js may exist only in the XSLT output.
	if (autoload) {
		window.xoverXsltReady.then(async () => {
			if (!window.loadXmlWithXsltFromBytes || !/^(text\/xml|application\/xml|.*\+xml)$/.test(document.contentType)) return;
			if (document.readyState === 'loading') await new Promise(resolve => document.addEventListener('DOMContentLoaded', resolve, { once: true }));
			const bytes = new TextEncoder().encode(new XMLSerializer().serializeToString(document));
			await window.loadXmlWithXsltFromBytes(bytes, location.href);
		}).catch(error => {
			console.error('Unable to initialize XML stylesheet', error);
			if (document.documentElement) document.documentElement.textContent = `Unable to initialize XML stylesheet: ${error.message}`;
		});
	}
})();
