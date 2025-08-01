use crate::errors::AppError;
use crate::models::auth::Claims;
use crate::services::AuthService;
use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
};
use axum_extra::TypedHeader;
use axum_extra::headers::{Authorization, authorization::Bearer};
use sqlx::PgPool;
use std::sync::Arc;

/// Authentication middleware that validates JWT tokens and adds user claims to request extensions
pub async fn auth_middleware(
    State(auth_service): State<Arc<AuthService>>,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing authorization header".to_string()))?;

    // Extract token from header
    let token = auth_service.extract_token_from_header(auth_header)?;

    // Validate token and get claims
    let claims = auth_service.validate_token(token)?;

    // Verify user still exists in database
    auth_service.get_current_user(&pool, &claims).await?;

    // Add claims to request extensions so handlers can access them
    request.extensions_mut().insert(claims);

    // Continue to next middleware/handler
    Ok(next.run(request).await)
}

/// Optional authentication middleware - allows both authenticated and anonymous access
/// If token is provided, it validates and adds claims; if not, continues without claims
pub async fn optional_auth_middleware(
    State(auth_service): State<Arc<AuthService>>,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    // Try to extract Authorization header
    if let Some(auth_header) = headers
        .get("authorization")
        .and_then(|header| header.to_str().ok())
    {
        // Try to extract and validate token
        if let Ok(token) = auth_service.extract_token_from_header(auth_header) {
            if let Ok(claims) = auth_service.validate_token(token) {
                // Verify user exists (optional check)
                if auth_service.get_current_user(&pool, &claims).await.is_ok() {
                    request.extensions_mut().insert(claims);
                }
            }
        }
    }

    // Continue regardless of authentication status
    next.run(request).await
}

/// Admin-only middleware that requires admin role
pub async fn admin_middleware(
    State(auth_service): State<Arc<AuthService>>,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // First run auth middleware logic
    let auth_header = headers
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing authorization header".to_string()))?;

    let token = auth_service.extract_token_from_header(auth_header)?;
    let claims = auth_service.validate_token(token)?;

    // Verify user exists
    auth_service.get_current_user(&pool, &claims).await?;

    // Check admin role
    if !auth_service.is_admin(&claims) {
        return Err(AppError::Unauthorized("Admin access required".to_string()));
    }

    // Add claims to request extensions
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Resource ownership middleware - ensures user can only access their own resources
/// Requires a way to extract the resource owner ID from the request
pub async fn ownership_middleware<F>(
    State(auth_service): State<Arc<AuthService>>,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
    get_resource_owner: F,
) -> Result<Response, AppError>
where
    F: Fn(&Request) -> Option<uuid::Uuid>,
{
    // First authenticate the user
    let auth_header = headers
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing authorization header".to_string()))?;

    let token = auth_service.extract_token_from_header(auth_header)?;
    let claims = auth_service.validate_token(token)?;

    // Verify user exists
    auth_service.get_current_user(&pool, &claims).await?;

    // Get resource owner ID
    if let Some(resource_owner_id) = get_resource_owner(&request) {
        // Check if user can access the resource
        if !auth_service.can_access_resource(&claims, resource_owner_id) {
            return Err(AppError::Unauthorized(
                "You don't have permission to access this resource".to_string(),
            ));
        }
    }

    // Add claims to request extensions
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Utility function to extract claims from request extensions
/// This is used in handlers to get the authenticated user's information
pub fn extract_claims(request: &Request) -> Result<&Claims, AppError> {
    request
        .extensions()
        .get::<Claims>()
        .ok_or_else(|| AppError::Unauthorized("No authentication information found".to_string()))
}

/// Utility function to extract optional claims from request extensions
/// Returns None if no authentication information is present
pub fn extract_optional_claims(request: &Request) -> Option<&Claims> {
    request.extensions().get::<Claims>()
}

/// TypedHeader extractor for Bearer tokens (alternative approach)
pub async fn extract_bearer_token(
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
) -> Result<String, AppError> {
    Ok(authorization.token().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::auth::{JwtConfig, UserRole};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use uuid::Uuid;

    fn create_test_claims() -> Claims {
        Claims {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            role: UserRole::User,
            exp: chrono::Utc::now().timestamp() + 3600, // 1 hour from now
            iat: chrono::Utc::now().timestamp(),
            sub: "testuser".to_string(),
        }
    }

    fn create_admin_claims() -> Claims {
        Claims {
            user_id: Uuid::new_v4(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            role: UserRole::Admin,
            exp: chrono::Utc::now().timestamp() + 3600,
            iat: chrono::Utc::now().timestamp(),
            sub: "admin".to_string(),
        }
    }

    #[test]
    fn test_extract_claims() {
        let mut request = Request::builder().body(Body::empty()).unwrap();

        let claims = create_test_claims();
        request.extensions_mut().insert(claims.clone());

        let extracted_claims = extract_claims(&request).unwrap();
        assert_eq!(extracted_claims.username, "testuser");
        assert_eq!(extracted_claims.role, UserRole::User);
    }

    #[test]
    fn test_extract_optional_claims() {
        let mut request = Request::builder().body(Body::empty()).unwrap();

        // No claims inserted
        assert!(extract_optional_claims(&request).is_none());

        // Insert claims
        let claims = create_test_claims();
        request.extensions_mut().insert(claims.clone());

        let extracted_claims = extract_optional_claims(&request).unwrap();
        assert_eq!(extracted_claims.username, "testuser");
    }

    #[test]
    fn test_extract_claims_missing() {
        let request = Request::builder().body(Body::empty()).unwrap();

        let result = extract_claims(&request);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Unauthorized(msg) => {
                assert_eq!(msg, "No authentication information found");
            }
            _ => panic!("Expected Unauthorized error"),
        }
    }
}
