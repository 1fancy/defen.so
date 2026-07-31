# Defenso (.NET)

Fail-open ASP.NET Core middleware.

## Install

```bash
dotnet add package Defenso
```

## Use

```csharp
using Defenso;

app.UseDefenso(o =>
{
    o.Token = Environment.GetEnvironmentVariable("DEFENSO_TOKEN");
});
```

## Status

Scaffold — this SDK currently passes every request through and does not yet inspect, block, cache policy, or forward attack logs. For working protection today use the CNAME edge (point your domain at guard.defen.so — full WAF, no code) or the Node/PHP SDKs.

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-dotnet)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
