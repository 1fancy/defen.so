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
