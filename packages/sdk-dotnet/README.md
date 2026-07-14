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

## Fail-open contract

Same guarantees as the Node SDK.

## Status

Alpha scaffold.

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-dotnet)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
