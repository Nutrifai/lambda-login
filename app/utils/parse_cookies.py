def parse_cookies(cookies: str) -> dict[str, str]:
    if not cookies:
        return {}

    return {
        name: value
        for name, value in
        [cookie.split("=") for cookie in cookies.split(";")]
    }