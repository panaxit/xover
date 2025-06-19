import { dotnet } from './dotnet.js';

let wasmExports;

// 1) bootstrap the .NET runtime exactly once
(async () => {
    const host = await dotnet.create({ loadDebugSymbols: false });
    const config = host.getConfig();
    wasmExports = await host.getAssemblyExports(config.mainAssemblyName);
    // now tell the main thread we’re ready
    self.postMessage({ ready: true });
})();

// 2) handle each transform request
self.addEventListener('message', ({ data }) => {
    const { id, xml, xsl, params } = data;

    try {
        let result;
        if (params !== undefined) {
            // ensure params is JSON
            const jsonParams = typeof params === 'string'
                ? params
                : JSON.stringify(params);
            result = wasmExports.XmlTransform.Program.TransformXml(xml, xsl, jsonParams);
        } else {
            result = wasmExports.XmlTransform.Program.TransformXml(xml, xsl);
        }

        self.postMessage({ id, result });
    }
    catch (err) {
        // don’t let the worker crash
        self.postMessage({ id, error: err.message || String(err) });
    }
});