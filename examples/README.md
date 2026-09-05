# Examples Directory

This directory contains simple example Dockerfiles and configurations that demonstrate how to use i0's hardened base Docker images in real-world applications.

## Important Notice

**These examples are for demonstration purposes only.** The version tags in these Dockerfiles use `:latest` as placeholders and are NOT kept up-to-date. They may reference outdated images with security vulnerabilities.

**For production use, always replace `:latest` with current version tags from the [officially published images](https://github.com/orgs/interrzero/packages?repo_name=base-docker-images).**

## Available Examples

### Go Application (`Dockerfile.example.go`)

- **Purpose**: Demonstrates building a Go application using our `go-base` image
- **Architecture**: Multi-stage build (build -> minimal static runtime)
- **Features**: 
  - Uses hardened Go base image for compilation
  - Outputs to Chainguard's static image for minimal attack surface
  - Proper non-root user handling
  - Displays version information from base image

### Nginx + Node.js Application (`Dockerfile.example.nginx`)

- **Purpose**: Shows how to build a frontend application and serve it with Nginx
- **Architecture**: Multi-stage build (Node.js build -> Nginx runtime)
- **Features**:
  - Uses `nodejs-base` for building frontend assets
  - Uses `nginx-base` for serving static files
  - Custom Nginx configuration included
  - Security-focused configuration

### FIPS Application (`Dockerfile.example.fips`)

- **Purpose**: Demonstrates building on our `fips-140-3` image, which ships the CMVP-validated OpenSSL FIPS Provider 3.1.2 (certificate [#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985)) already active in approved mode
- **Architecture**: Single stage on the FIPS base, with a build-time assertion that approved mode is enforced
- **Features**:
  - No OpenSSL configuration required: `OPENSSL_CONF` and `OPENSSL_MODULES` are inherited from the base image
  - Shows that enforcement reaches the application runtime, not just the `openssl` CLI - `hashlib.md5()` is refused while `hashlib.sha256()` works
  - Includes a startup assertion pattern worth copying: it checks that a **non-approved** algorithm fails, which is the only check that distinguishes "enforcing" from "module merely loaded"

> **Compliance note:** read [FIPS.md](../FIPS.md) before making any claim about an image built this way. It is built from CMVP-validated source per the Security Policy and is *user-affirmed* for this operating environment. It is **not** "FIPS 140-3 validated on Wolfi" - no such validation entry exists.
>
> The older `fips-base` image (FIPS 140-2, certificates #4282/#4811) was **retired on 2026-09-21** when those certificates reached their sunset. It is no longer built, and tags published before then no longer receive CVE patches. See the [migration notes](../FIPS.md#migrating-from-fips-base-to-fips-140-3) - the change from musl to glibc is the part that needs attention.

### Supporting Files

- **`default.conf`**: Example Nginx configuration with security hardening
- **`go-app/`**: Simple "Hello World" Go application with module definition  
- **`frontend-app/`**: Minimalist Node.js frontend app 
- **`fips-app/`**: Minimal Python app that prints its OpenSSL version and demonstrates that a non-approved digest is refused

## Usage

To use these examples as starting points:

1. **Copy the relevant Dockerfile** to your project
2. **Replace `:latest` tags** with current version tags from [GHCR packages](https://github.com/orgs/interrzero/packages?repo_name=base-docker-images)
3. **Modify** the example to fit your application's specific needs
4. **Test locally** before deploying to any higher enviuronments.  Be thorough in your testing/validation.

## Getting Current Image References

For the most up-to-date image references, see:
- [Latest Releases](https://github.com/interrzero/base-docker-images/releases)
- [GHCR Package Registry](https://github.com/orgs/interrzero/packages?repo_name=base-docker-images)
- Repository README for current version information

## Best Practices

When adapting these examples:
- Always use SHA pinning for reproducible builds
- Add the `--pull` flag to your `docker build` commands
- Run container structure tests before deployment
- Follow the principle of least privilege (non-root users)
- Use multi-stage builds to minimize final image size