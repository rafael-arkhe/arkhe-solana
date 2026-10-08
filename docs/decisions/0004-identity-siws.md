# ADR 0004: Identity and Authorization - SIWS and RBAC

## Status
Accepted

## Context
Arkhe interacts heavily with blockchain (Solana) primitives and Web3 users. Traditional password-based authentication introduces unnecessary friction and security vectors. We need a secure, standardized way for users (creators, auditors, admins) to authenticate and authorize actions.

## Decision
We will adopt **Sign-In With Solana (SIWS)** as our primary authentication mechanism and implement a simple **Role-Based Access Control (RBAC)** for authorization.

*   **Authentication:** SIWS is the standard for dApps. It allows users to authenticate by signing a standardized message with their Solana wallet. Passwords will not be used.
*   **Authorization:** A simple RBAC model will be implemented, assigning roles such as `creator`, `auditor`, and `admin` to authenticated wallets.
*   **Rate Limiting:** Authentication and API access will be protected by IP and wallet-based rate limiting using `tower-governor`.

## Consequences
*   Frictionless authentication for Web3-native users.
*   Elimination of password management and related vulnerabilities.
*   More complex authorization (ABAC for compliance) and traditional SSO (OAuth2/OIDC) are explicitly deferred to later stages.
