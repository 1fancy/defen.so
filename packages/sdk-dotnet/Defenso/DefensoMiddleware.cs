namespace Defenso;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

public class DefensoOptions
{
    public string? Token { get; set; }
    public string ApiUrl { get; set; } = "https://app.defen.so";
}

public static class DefensoExtensions
{
    public static IApplicationBuilder UseDefenso(this IApplicationBuilder app, Action<DefensoOptions> configure)
    {
        var options = new DefensoOptions();
        configure(options);
        return app.Use(async (ctx, next) =>
        {
            // TODO: policy check + async attack-log ingest
            await next();
        });
    }
}
