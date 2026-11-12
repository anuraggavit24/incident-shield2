def test_paypal_error_names_the_reason_without_leaking_credentials() -> None:
    import httpx

    from app.paypal_client import _reason

    body = {
        "name": "UNPROCESSABLE_ENTITY",
        "details": [{"issue": "PAYEE_ACCOUNT_RESTRICTED", "field": "/payee"}],
        "debug_id": "abc123",
        "access_token": "should-never-appear",
    }
    text = _reason(httpx.Response(422, json=body))
    assert text == " (UNPROCESSABLE_ENTITY, PAYEE_ACCOUNT_RESTRICTED, /payee, debug_id abc123)"
    assert _reason(
        httpx.Response(401, json={"error": "invalid_client", "error_description": "Client Authentication failed"})
    ) == (" (invalid_client, Client Authentication failed)")
    assert _reason(httpx.Response(500, text="<html>")) == "" and _reason(httpx.Response(400, json=["x"])) == ""
