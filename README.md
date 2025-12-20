# Cirreum.Authorization.SignedRequest.Client

A lightweight .NET client SDK for HMAC-signed HTTP request authentication. Use this package to sign outgoing HTTP requests for APIs that require signed request authentication.

## Installation

```shell
dotnet add package Cirreum.Authorization.SignedRequest.Client
```

## Quick Start

```csharp
using System.Net.Http;

// Store your credentials securely (e.g., from configuration)
var credentials = new SigningCredentials("your-client-id", "your-signing-secret");

// Create and sign a request
var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/data");
await request.SignRequestAsync(credentials);

// Send the signed request
using var client = new HttpClient();
var response = await client.SendAsync(request);
```

## Usage

### Signing a Request

The `SignRequestAsync` extension method adds the required authentication headers to your HTTP request:

```csharp
var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/orders");
request.Content = new StringContent(json, Encoding.UTF8, "application/json");

// Sign with credentials object
await request.SignRequestAsync(credentials);

// Or sign with individual values
await request.SignRequestAsync("client-id", "signing-secret");
```

### Sending Signed Requests

Use the `SendSignedAsync` extension methods on `HttpClient` for a streamlined experience:

```csharp
using var client = new HttpClient { BaseAddress = new Uri("https://api.example.com") };

// Send a signed GET request
var request = new HttpRequestMessage(HttpMethod.Get, "/data");
var response = await client.SendSignedAsync(request, credentials);

// Send a signed POST with JSON body
var order = new { ProductId = 123, Quantity = 2 };
var response = await client.SendSignedAsync(
    HttpMethod.Post,
    "/orders",
    credentials,
    content: order);
```

### Custom Options

Configure signing behavior with `SigningOptions`:

```csharp
var options = new SigningOptions {
    IncludeQueryString = true,              // Include query string in signature (default: true)
    SignatureVersion = "v1",                // Signature version prefix (default: "v1")
    ClientIdHeaderName = "X-Client-Id",     // Custom header names if needed
    TimestampHeaderName = "X-Timestamp",
    SignatureHeaderName = "X-Signature"
};

await request.SignRequestAsync(credentials, options);
```

## How It Works

The SDK generates signatures using HMAC-SHA256 with the following canonical request format:

```
{timestamp}.{method}.{path}.{bodyHash}
```

Where:
- **timestamp**: Unix timestamp (seconds since epoch)
- **method**: HTTP method in uppercase (GET, POST, etc.)
- **path**: Request path including query string (if enabled)
- **bodyHash**: SHA256 hash of the request body (or empty string hash for bodyless requests)

Three headers are added to each signed request:
- `X-Client-Id`: Your public client identifier
- `X-Timestamp`: Unix timestamp when the request was signed
- `X-Signature`: HMAC signature in format `v1={hex-encoded-signature}`

## Security Notes

- **Keep your signing secret secure** - never commit it to source control
- Store credentials in secure configuration (Azure Key Vault, AWS Secrets Manager, etc.)
- Requests should be sent immediately after signing to avoid timestamp expiration
- Server-side validation typically allows a 2-minute tolerance for clock skew

## Requirements

- .NET 10.0 or later (uses C# 14 extension blocks)

## License

MIT License - see LICENSE file for details.
