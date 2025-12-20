# Cirreum.Authorization.SignedRequest.Client

A lightweight .NET client SDK for HMAC-signed HTTP request authentication. Sign outgoing HTTP requests and validate incoming webhooks with HMAC-SHA256 signatures.

## Installation

```shell
dotnet add package Cirreum.Authorization.SignedRequest.Client
```

## Features

- **Sign outgoing requests** - Add HMAC-SHA256 signatures to HTTP requests
- **Validate incoming webhooks** - Verify signatures on incoming requests
- **Allocation-free validation** - Uses `Span<byte>` for efficient body hashing
- **Customizable headers** - Configure header names and options
- **ASP.NET Core integration** - Extension methods for `HttpRequest`

## Sending Signed Requests

### Quick Start

```csharp
using System.Net.Http;

var credentials = new SigningCredentials("your-client-id", "your-signing-secret");

using var client = new HttpClient();
var response = await client.SendSignedAsync(
    HttpMethod.Post,
    "https://api.example.com/orders",
    credentials,
    content: new { ProductId = 123, Quantity = 2 });
```

### Sign a Request

```csharp
var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/orders");
request.Content = new StringContent(json, Encoding.UTF8, "application/json");

// Sign with credentials object
await request.SignRequestAsync(credentials);

// Or sign with individual values
await request.SignRequestAsync("client-id", "signing-secret");

// Then send
var response = await client.SendAsync(request);
```

### Send Signed Requests

```csharp
using var client = new HttpClient { BaseAddress = new Uri("https://api.example.com") };

// Send a signed request
var request = new HttpRequestMessage(HttpMethod.Get, "/data");
var response = await client.SendSignedAsync(request, credentials);

// Send with JSON body (auto-serialized)
var response = await client.SendSignedAsync(
    HttpMethod.Post,
    "/orders",
    credentials,
    content: new { ProductId = 123 });
```

### Signing Options

```csharp
var options = new SigningOptions {
    IncludeQueryString = true,           // Include query string in signature (default: true)
    SignatureVersion = "v1",             // Signature version prefix (default: "v1")
    ClientIdHeaderName = "X-Client-Id",  // Custom header names
    TimestampHeaderName = "X-Timestamp",
    SignatureHeaderName = "X-Signature"
};

await request.SignRequestAsync(credentials, options);
```

## Receiving Webhooks

### Quick Start

```csharp
using Microsoft.AspNetCore.Http;

app.MapPost("/webhooks/events", async (HttpRequest request) => {
    var result = await request.ValidateSignatureAsync("whsec_your_webhook_secret");

    if (!result.IsValid) {
        return Results.Unauthorized();
    }

    var clientId = request.GetSignedRequestClientId();
    // Process webhook...

    return Results.Ok();
});
```

### Throw on Invalid Signature

```csharp
app.MapPost("/webhooks/events", async (HttpRequest request) => {
    await request.ValidateSignatureOrThrowAsync("whsec_your_webhook_secret");

    // Process webhook - only reached if signature is valid
    return Results.Ok();
});
```

### Validation Options

```csharp
var options = new ValidationOptions {
    TimestampTolerance = TimeSpan.FromMinutes(5),      // Max age of requests (default: 5 min)
    FutureTimestampTolerance = TimeSpan.FromMinutes(1), // Clock skew allowance (default: 1 min)
    IncludeQueryString = true,                          // Must match sender config
    SupportedSignatureVersions = ["v1"]                 // Supported versions
};

var result = await request.ValidateSignatureAsync(secret, options);
```

### Manual Validation

For non-ASP.NET Core scenarios or custom handling:

```csharp
var validator = new SignedRequestValidator(options);

var result = validator.Validate(
    body: bodyBytes,
    signature: "v1=abc123...",
    timestamp: 1734567890,
    httpMethod: "POST",
    path: "/webhooks/events",
    signingSecret: "whsec_your_secret");

if (!result.IsValid) {
    Console.WriteLine($"Validation failed: {result.ErrorMessage}");
}
```

## How It Works

The SDK generates signatures using HMAC-SHA256 with the following canonical request format:

```
{timestamp}.{method}.{path}.{bodyHash}
```

Where:
- **timestamp**: Unix timestamp (seconds since epoch)
- **method**: HTTP method in uppercase (GET, POST, etc.)
- **path**: Request path including query string (if configured)
- **bodyHash**: SHA256 hash of the request body (or empty string hash for bodyless requests)

Three headers are added to each signed request:
- `X-Client-Id`: Your public client identifier
- `X-Timestamp`: Unix timestamp when the request was signed
- `X-Signature`: HMAC signature in format `v1={hex-encoded-signature}`

## Security Notes

- **Keep your signing secret secure** - never commit it to source control
- Store credentials in secure configuration (Azure Key Vault, AWS Secrets Manager, etc.)
- Requests should be sent immediately after signing to avoid timestamp expiration
- The default 5-minute timestamp tolerance protects against replay attacks
- Use separate secrets for API authentication vs webhook validation

## Requirements

- .NET 10.0 or later

## License

MIT License - see LICENSE file for details.
