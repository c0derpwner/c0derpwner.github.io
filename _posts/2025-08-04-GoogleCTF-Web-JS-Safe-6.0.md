---
title: Web - JS Safe 6.0 - GoogleCTF
published: true
---


Challenge description: You stumbled upon someone's "JS Safe" on the web. It's a simple HTML file that can store secrets in the browser's localStorage. This means that you won't be able to extract any secret from it (the secrets are on the computer of the owner), but it looks like it was hand-crafted to work only with the password of the owner. Another year, another JS Safe challenge! I'm always looking forward to this challenge during Google CTF.


Opening the HTML file, we see this suspect code:

![](/assets/js_safe1.png)

But it appears to be just the background cube.

The "usage instructions" to unlock the safe are:

    Open the page in Chrome (the only supported browser)
    Open Dev Tools and type:
    anti(debug); // Industry-leading antidebug!
    unlock("password"); // -> alert(secret)

A "render loop" is created using `setInterval(renderFrame, frameInterval)` which spams the DevTools console (with `clear()` and the "usage instructions").

Scrolling further down the file, now comes the juicy parts, the `anti(debug)` function:

![](/assets/js_safe2.png)


A bunch of "looks like space but is another character"-symbols are in use. From previous years' JS Safe challenges we know that replacing these bytes with proper spaces will most likely break the code.

Finally the unlock function looks fairly simple:

![](/assets/js_safe3.png)


From my understanding it is going to instrument the prototype of lots of common things (arrays, console, etc) such that when calling .get (i.e. property access), the step-value will be incremented. This means we can't just sprinkle console.log calls everywhere, as that would increase the step value and break the decryption logic.
Further anti-debugging in instrument

When initially calling anti(...) we pass the variable debug [1], which ends up inside instrument() that checks two conditions:
document.documentElement.outerHTML.length !== 14347
This is fairly easy to bypass, whenever I change the source file I need to update the "total document length".

But the next check is even weirder:

debug(f, "window.c && function perf(){ const l = `" + f + "`.length; window.step += l; }() // poor man's 'performance counter`");
Normally f.length would be the string length of the function f, but why the backticks (template literals)? What does f expand to?
But what looks even more suspicious is the comment which quotes using a single-quote and end the quote with a backtick (spider senses tingling!)
Modifying the code



Let's start by commenting the console.clear(); and console.log(content); to improve the debugging experience. This adds 4 extra characters, so we also need to update the outerHTML.length check:

```diff
220,221c220,221
<     console.clear();
<     console.log(content);
---
>     //console.clear();
>     //console.log(content);
285c285
<     debug(f, "document.documentElement.outerHTML.length !== 14347");
---
>     debug(f, "document.documentElement.outerHTML.length !== 14351");
```

But keeping track of outerHTML is a bit tedious, so another minimal modification is to change the outerHTML statement from !== realSize to === falseSize, i.e. the logic is the same, but we don't need to update the value when modifying the rest of the file:

```diff
285c285
<     debug(f, "document.documentElement.outerHTML.length !== 14347");
---
>     debug(f, "document.documentElement.outerHTML.length === 99999");
```

Note: why not just change it to "false" ? We believe the check-function will verify check.toString().length, but we are a bit unsure how - so lets not modify the length of the check-function but doesn't work....

I get this warning when opening the modified challenge file in my browser:

```bash
Refused to execute inline script because it violates the following Content Security Policy directive: 
"script-src 'sha256-P8konjutLDFcT0reFzasbgQ2OTEocAZB3vWTUbDiSjM=' 'sha256-eDP6HO9Yybh41tLimBrIRGHRqYoykeCv2OYpciXmqcY=' 'unsafe-eval'".
Either the 'unsafe-inline' keyword, a hash ('sha256-C7RyoweJ1Looccbu94IGsrn5T/cazOvY7o8EuZZPQJA='), 
or a nonce ('nonce-...') is required to enable inline execution.
```

In the top of the HTML file, we see this inlined CSP:

```html
<meta http-equiv="Content-Security-Policy" id="c" content="script-src 'sha256-P8konjutLDFcT0reFzasbgQ2OTEocAZB3vWTUbDiSjM=' 'sha256-eDP6HO9Yybh41tLimBrIRGHRqYoykeCv2OYpciXmqcY=' 'unsafe-eval'">
```

We could just remove the CSP completely, but we want to keep the changes minimal. Again the spider senses are tingling, why does the CSP have id="c"? Why would a CSP-meta element ever need an ID?
Remember the instrument contained this code window.c && function perf(){ ... }, but also at the very top of the anti(debug)-function we see:

```html

window.step = 0;
window.cﾠ= true; // Countﾠstepsﾠwith debug (prototype instrumentation is separate)
window.success = false;
```


So clearly window.c is true regardless of the CSP HTML element, right? Spoiler: No, as I later learned, the whitespace after window.c (i.e. window.c[HERE]=true;) is not actually a whitespace, but a valid javascript identifier, meaning window.c != window.cﾠ!

Our new modification to the file is now:

```diff
7c7
< <meta http-equiv="Content-Security-Policy" id="c" content="script-src 'sha256-P8konjutLDFcT0reFzasbgQ2OTEocAZB3vWTUbDiSjM=' 'sha256-eDP6HO9Yybh41tLimBrIRGHRqYoykeCv2OYpciXmqcY=' 'unsafe-eval'">
---
> <meta http-equiv="Content-Security-Policy" id="c" content="script-src 'unsafe-inline' 'unsafe-eval'">
```



## Setting breakpoints

A quick'n'dirty way of solving the challenge would be setting a breakpoint on `flag[0] == pool[...]` and bruteforce one flag character at a time. But setting a breakpoint in DevTools doesn't trigger?!  Lets go up one level and set a breakpoint on `anti(debug)`, this should work as nothing weird has been run before that call. Stepping though `anti(debug)`, we see another sneaky trick, in `renderFrame()` the call to `multiline(...)` (logic for the big spinning cube) has redefines the global `r` function to become `ROT-47`, so now the cube block decrypts as:

![](/assets/js_safe4.png)



This checks `c.outerHTML.length*2 == 386 && (new Error).stack.split('eval').length>4`

So if we change the length of the CSP or the stack trace is not correct, then `window.step` will be set to a wrong value and the decryption will not work! We fix this by padding the CSP with spaces. 

#### Escaping the debugger

We know `instrument`is called with the prototypes of many common values, so I uncommented that (inside anti(debug)) 
and added: `[].flat().concat(check, eval).forEach(instrument);`.
We can't step into the `debug(f, "...")` function, but we can replace it with a `console.log(...)` to figure out what that `f` expands to:
![](/assets/js_safe5.png)

This gives us the following code being run in the "debug context":

![](/assets/js_safe6.png)


Now we finally see the check()-code properly expanded (and the while(true) debugger active).
We also see the rest of the build-in functions will not "escape", as they will expand into the string "[native code]", e.g. for eval this gives:

```js
window.c && function perf(){ const l = `function eval() { [native code] }`.length; window.step += l; }() // poor man's 'performance counter`
```


## b'\xef\xbe\xa0' as a valid identifier


Another cool trick; remember how the global function `r` was overriden in `check()`, i.e:

```javascript
window.k // ROT13 TODO:ﾠuse thisfor anﾠadditional encryption layerﾠ
= function(s){returnt toString().replace(/[a-z]/gi,c=>(c=c.charCodeAt(),String.fromCharCode((c&95)<78?c+13:c-13)));}
```

But actually that "space" (`\xef\xbe\xa0`) in front of the equals symbol (`[HERE]= function { ... }`) is a valid javascript identifier!

This means that the following code:

```javascript
let pool =ﾠ`?o>\`Wn0o0U0N?05o0ps}q0|mt\`ne\`us&400_pn0ss_mph_0\`5`;
pool = r(pool);
```

Is actually two(!) function calls, first `tmp = \xef\xbe\xa0("?o>...5")` then `pool = r(tmp)`.

Furthermore the _looks like space but isn't_ symbol is also used in the function `double`

```javascript
const double = Function.call`window.stepﾠ*= 2`;
```

So the above code will not change `window.step` when called (but instead change `"window.stepﾠ"` variable).

### Modifying `check()` and printing flag chars

Now we're comfortable modifying the `check()` code and patching out `check.toString().length !== 914` anti-debug trick.

We can modify the `while (!window.success) { ... }` loop such that instead of comparing each flag char, we print the expected value and continue.


![](/assets/js_safe_final.png)

