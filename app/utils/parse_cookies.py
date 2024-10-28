def parse_cookies(cookies: str) -> dict[str, str]:
    """
    Parse a cookie string into a dictionary. By converting the cookie string into a dictionary,
    the function makes it easier to access and manipulate the cookies.

    Args:
        cookies (str): The cookie string to parse.

    Returns:
        dict[str, str]: A dictionary where the keys are cookie names and the values are cookie values.
    """
    if not cookies:
        return {}

    return {
        name: value
        for name, value in
        [cookie.split("=") for cookie in cookies.split(";")]
    }
