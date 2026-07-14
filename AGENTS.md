# Development guidance

Keep the service dependency-free outside the Go standard library. Preserve streaming behavior for Git fetches and pushes. Authentication and redirect changes require tests. Never log OAuth codes, access tokens, authorization headers, or complete OAuth query strings.
